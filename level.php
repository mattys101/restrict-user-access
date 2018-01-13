<?php
/**
 * @package Restrict User Access
 * @author Joachim Jensen <jv@intox.dk>
 * @license GPLv3
 * @copyright 2017 by Joachim Jensen
 */

if (!defined('ABSPATH')) {
	exit;
}

final class RUA_Level_Manager {

	/**
	 * Metadata
	 *
	 * @var WPCAObjectManager
	 */
	private $metadata;

	/**
	 * Access Levels
	 *
	 * @var array
	 */
	private $levels            = array();

	/**
	 * User level capabilities
	 * @var array
	 */
	private $user_levels_caps  = array();

	/**
	 * Constructor
	 */
	public function __construct() {

		if(is_admin()) {
			new RUA_Level_Overview();
			new RUA_Level_Edit();
		}

		$this->add_actions();
		$this->add_filters();

		add_shortcode( 'restrict', array($this,'shortcode_restrict'));
	}

	/**
	 * Add callbacks to actions queue
	 *
	 * @since 0.5
	 */
	protected function add_actions() {
		// if(!is_admin()) {
		// 	add_action( 'pre_get_posts',
		// 		array($this,'filter_nav_menus_query'));
		// }

		add_action('template_redirect',
			array($this,'authorize_access'));
		add_action('init',
			array($this,'create_restrict_type'),99);
		add_action( 'user_register',
			array($this,'registered_add_level'));
		add_action('wp_loaded', 
			array($this, 'init_protect_uploads'));
		add_action( 'generate_rewrite_rules', 
			array($this, 'generate_rewrite_rules') );
	}

	/**
	 * Add callbacks to filters queue
	 *
	 * @since 0.5
	 */
	protected function add_filters() {
		if(!is_admin()) {
			add_filter( 'wp_get_nav_menu_items',
				array($this,'filter_nav_menus'), 10, 3 );
		}

		//hook early, other plugins might add dynamic caps later
		//fixes problem with WooCommerce Orders
		add_filter( 'user_has_cap',
			array($this,'user_level_has_cap'), 9, 4 );
			
		// hook late to remove restricted posts from search results,
		// even if added by other filters.
		add_filter( 'posts_results', 
			array($this, 'filter_posts_results'), 10000, 2 );
		
	}
	
	/**
	 * Add rewrite rules for handling file access through WP.
	 * 
	 * @since  0.17.2-mattys101
	 * @param  WP_Rewrite $rewrite
	 * @return WP_Rewrite
	 */
	public function generate_rewrite_rules( $wp_rewrite ) {
		$upload_url = wp_upload_dir();
		$upload_url = $upload_url[ 'baseurl' ];
	    $regex = str_replace( site_url( '/' ), '', $upload_url );
	    $regex .= '/(.*)$';
	    $wp_rewrite->add_external_rule( $regex, 'index.php?file=$1' );
	    return $wp_rewrite;
	}
	
	/**
	 * Handle access to uploads and ensure users get access only if they 
	 * have an appropriate level, or there are no restrictions on the file.
	 * 
	 * @since  0.17.2-mattys101
	 */
	public function init_protect_uploads( ) {
    	if ( isset($_GET[ 'file' ]) ) {
    		$this->_authorize_file_access($_GET[ 'file' ]);
    	}
	}

	/**
	 * Filter navigation menu items by level
	 *
	 * @since  1.0
	 * @param  array   $items
	 * @param  string  $menu
	 * @param  array   $args
	 * @return array
	 */
	public function filter_nav_menus( $items, $menu, $args ) {
		if(!$this->_has_global_access()) {
			$user_levels = array_flip($this->get_user_levels());
			foreach( $items as $key => $item ) {
				$menu_levels = get_post_meta( $item->ID, '_menu_item_level', false );
				if($menu_levels && !array_intersect_key($user_levels, array_flip($menu_levels))) {
					unset($items[$key]);
				}
			}
		}
		return $items;
	}

	/**
	 * Filter navigation menu items by level
	 * using query
	 * Might have better performance
	 *
	 * @since  1.0
	 * @param  WP_Query  $query
	 * @return void
	 */
	public function filter_nav_menus_query( $query ) {
		if (isset($query->query['post_type'],$query->query['include']) && $query->query['post_type'] == 'nav_menu_item' && $query->query['include']) {
			$levels = $this->level_manager->get_user_levels();
			$meta_query = array();
			$meta_query[] = array(
				'key'     => '_menu_item_level',
				'value'   => 'wpbug',
				'compare' => 'NOT EXISTS'
			);
			if($levels) {
				$meta_query['relation'] = 'OR';
				$meta_query[] = array(
						'key'     => '_menu_item_level',
						'value'   => $levels,
						'compare' => 'IN'
					);
			}
			$query->set('meta_query',$meta_query);
		}
	}

	/**
	 * Get level by name
	 *
	 * @since  0.6
	 * @param  string  $name
	 * @return WP_Post|boolean
	 */
	public function get_level_by_name($name) {
		$all_levels = RUA_App::instance()->get_levels();
		$retval = false;
		foreach ($all_levels as $id => $level) {
			if($level->post_name == $name) {
				if($level->post_status == RUA_App::STATUS_ACTIVE) {
					$retval = $level;
				}
				break;
			}
		}
		return $retval;
	}

	/**
	 * Restrict content in shortcode
	 *
	 * @version 0.1
	 * @param   array     $atts
	 * @param   string    $content
	 * @return  string
	 */
	public function shortcode_restrict( $atts, $content = null ) {
		$a = shortcode_atts( array(
			'role'  => '',
			'level' => '',
			'page'  => 0
		), $atts );

		if(!$this->_has_global_access()) {
			if($a['level']) {
				$level = $this->get_level_by_name(ltrim($a['level'],'!'));
				if($level) {
					$not = $level->post_name != $a['level'];
					$user_levels = array_flip($this->get_user_levels());
					//when level is negated, hide content if user has it
					//when level is not negated, hide content if user does not have it
					if($not xor !isset($user_levels[$level->ID])) {
						$content = '';
					}
				}
			}
			else if($a['role'] !== '') {
				$roles = explode(',', $a['role']);
				if(array_search('0', $roles)) {
					_deprecated_argument( '[restrict]', '0.17', __('Use Access Level for logged-out users instead.','restrict-user-access'));
				}
				if(!array_intersect($roles, $this->get_user_roles())) {
					$content = '';
				}
			}
			// Only apply the page content if the user does not have access.
			if($a['page'] && !$content) {
				$page = get_post($a['page']);
				if($page) {
					setup_postdata($page);
					$content = get_the_content();
					wp_reset_postdata();
				}
			}
		}
		return do_shortcode($content);
	}
	
	/**
	 * Filters posts from the search results and archive pages if the current user cannot access them.
	 * 
	 * @since   0.17.2.matty101
	 * @param   array    $posts
	 * @param   WPQuery  $query
	 * @return  array
	 */
	public function filter_posts_results( $posts, $query ) {
		if ( !($query->is_search() || $query->is_archive()) || $this->_has_global_access())
			return $posts;
		
		$result = array();
		
		foreach ($posts as $post) {
			// TODO: how to handle teased content in search results?
			if ( !$this->_access_blocked($post) )
				$result[] = $post;
		} 
		
		return $result;
	}
	
	/**
	 * Check if a specific post can be accessed by the user.
	 * Returns the ID of the level that is blocking the user access if 
	 * any exist. Therefore, if !_access_blocked(...) is true, then 
	 * the user can access the content.
	 *
	 * NOTE: This is not particularly efficient in the backend; however,
	 *       since search results, for example, are typically paged, we
	 *       won't have to run this too many times in one go.
	 * 
	 * @since   0.17.2.matty101
	 * @param   WP_Post   $post_to_check 
	 * @return  int
	 */
	private function _access_blocked( $post_to_check ) {
		
		if (!$post_to_check) {
			return 0;
		}
		
		if ($this->_has_global_access()) {
			return 0;
		}
		
		if (is_numeric($post_to_check)) 
			$post_to_check = get_post($post_to_check);
		
		global $wp_query, $post;
		
		$temp_query = new WP_Query(array('p' => $post_to_check->ID, 'post_type' => $post_to_check->post_type));
		
		$posts = WPCACore::get_posts_in_context(RUA_App::TYPE_RESTRICT, $temp_query, $post_to_check);
		$kick = 0;
		
		if ($posts) {
			$user_levels = array_flip($this->get_user_levels());
			foreach ($posts as $post) {
				if(!isset($user_levels[$post->ID])) {
					$kick = $post->ID;
				} else {
					$kick = 0;
					break;
				}
			}

			if(!$kick && is_user_logged_in()) {
				$conditions = WPCACore::get_conditions(RUA_App::TYPE_RESTRICT);
				foreach ($conditions as $condition => $level) {
					//Check post type
					if(isset($posts[$level])) {
						$drip = get_post_meta($condition,RUA_App::META_PREFIX.'opt_drip',true);
						//Restrict access to dripped content
						if($drip && $this->metadata()->get('role')->get_data($level) === '') {
							$start = $this->get_user_level_start(null,$level);
							$drip_time = strtotime('+'.$drip.' days 00:00',$start);
							if(time() <= $drip_time) {
								$kick = $level;
							} else {
								$kick = 0;
								break;
							}
						} else {
							$kick = 0;
							break;
						}
					}
				}
			}
		}
		
		return $kick;
	}

	/**
	 * Get instance of metadata manager
	 *
	 * @since  1.0
	 * @return WPCAObjectManager
	 */
	public function metadata() {
		if(!$this->metadata) {
			$this->_init_metadata();
		}
		return $this->metadata;
	}

	/**
	 * Create and populate metadata fields
	 *
	 * @since  0.1
	 * @return void
	 */
	private function _init_metadata() {

		$this->metadata = new WPCAObjectManager();
		$this->metadata
		->add(new WPCAMeta(
			'role',
			__('Synchronized Role'),
			'',
			'select',
			array()
		),'role')
		->add(new WPCAMeta(
			'handle',
			_x('Action','option', 'restrict-user-access'),
			0,
			'select',
			array(
				0 => __('Redirect', 'restrict-user-access'),
				1 => __('Tease & Include', 'restrict-user-access')
			),
			__('Redirect to another page or show teaser.', 'restrict-user-access')
		),'handle')
		->add(new WPCAMeta(
			'page',
			__('Page'),
			0,
			'select',
			array(),
			__('Page to redirect to or display content from under teaser.', 'restrict-user-access')
		),'page')
		->add(new WPCAMeta(
			'duration',
			__('Duration'),
			'day',
			'select',
			array(
				'day'   => __('Day(s)','restrict-user-access'),
				'week'  => __('Week(s)','restrict-user-access'),
				'month' => __('Month(s)','restrict-user-access'),
				'year'  => __('Year(s)','restrict-user-access')
			),
			__('Set to 0 for unlimited.', 'restrict-user-access')
		),'duration')
		->add(new WPCAMeta(
			'caps',
			__('Capabilities'),
			array(),
			'',
			array(),
			''
		),'caps');

		apply_filters('rua/metadata',$this->metadata);
	}

	/**
	 * Populate input fields for metadata
	 *
	 * @since  0.8
	 * @return void
	 */
	public function populate_metadata() {

		$role_list = array(
			'' => __('-- None --','restrict-user-access'),
			-1 => __('Logged-in','restrict-user-access'),
			0  => __('Not logged-in','restrict-user-access')
		);

		foreach(get_editable_roles() as $id => $role) {
			$role_list[$id] = $role['name'];
		}

		$this->metadata()->get('role')->set_input_list($role_list);
	}

	/**
	 * Create restrict post type and add it to WPCACore
	 *
	 * @since  0.1
	 * @return void
	 */
	public function create_restrict_type() {

		// Register the sidebar type
		register_post_type(RUA_App::TYPE_RESTRICT,array(
			'labels'        => array(
				'name'               => __('Access Levels', 'restrict-user-access'),
				'singular_name'      => __('Access Level', 'restrict-user-access'),
				'add_new'            => _x('Add New', 'level', 'restrict-user-access'),
				'add_new_item'       => __('Add New Access Level', 'restrict-user-access'),
				'edit_item'          => __('Edit Access Level', 'restrict-user-access'),
				'new_item'           => __('New Access Level', 'restrict-user-access'),
				'all_items'          => __('Access Levels', 'restrict-user-access'),
				'view_item'          => __('View Access Level', 'restrict-user-access'),
				'search_items'       => __('Search Access Levels', 'restrict-user-access'),
				'not_found'          => __('No Access Levels found', 'restrict-user-access'),
				'not_found_in_trash' => __('No Access Levels found in Trash', 'restrict-user-access'),
				'parent_item_colon'  => __('Extend Level', 'restrict-user-access')
			),
			'capabilities'  => array(
				'edit_post'          => RUA_App::CAPABILITY,
				'read_post'          => RUA_App::CAPABILITY,
				'delete_post'        => RUA_App::CAPABILITY,
				'edit_posts'         => RUA_App::CAPABILITY,
				'delete_posts'       => RUA_App::CAPABILITY,
				'edit_others_posts'  => RUA_App::CAPABILITY,
				'publish_posts'      => RUA_App::CAPABILITY,
				'read_private_posts' => RUA_App::CAPABILITY
			),
			'public'              => false,
			'hierarchical'        => true,
			'exclude_from_search' => true,
			'publicly_queryable'  => false,
			'show_ui'             => false,
			'show_in_menu'        => false,
			'show_in_nav_menus'   => false,
			'show_in_admin_bar'   => false,
			'has_archive'         => false,
			'rewrite'             => false,
			'query_var'           => false,
			'supports'            => array('title','page-attributes'),
			'can_export'          => false,
			'delete_with_user'    => false
		));

		WPCACore::types()->add(RUA_App::TYPE_RESTRICT);
	}

	/**
	 * Add level to user
	 *
	 * NOTE: Since 0.16.1-mattys101, changed to use 'update_user_meta' to 
	 *       ensure re-adding an expired level is correctly treated as adding 
	 *       a new level.
	 *
	 * @since  0.3
	 * @param  int           $user_id
	 * @param  int           $level_id
	 * @return int|boolean
	 */
	public function add_user_level($user_id,$level_id) {
		if(!$this->has_user_level($user_id,$level_id)) {
			$this->reset_user_levels_caps( $user_id );
			$user_level = true;
			
			if ( !in_array($level_id, get_user_meta($user_id, RUA_App::META_PREFIX.'level', $level_id)) ) {
				$user_level = add_user_meta( $user_id, RUA_App::META_PREFIX.'level', $level_id, false);
			}
			
			if($user_level) {
				update_user_meta($user_id, RUA_App::META_PREFIX.'level_'.$level_id, time());
			}
			
			return $level_id;
		}
		return false;
	}
	
	/**
	 * Renew a level to user, only if the level is currently held and has a duration.
	 * Returns FALSE if the renewal is not performed.
	 *
	 * If $once_per_period is TRUE (the default), the membership is not renewed if the
	 * latest renewal is already in the future. That is, only one renewal can be performed 
	 * per period. Setting $once_per_period to FALSE will allow multiple renews to be
	 * performed, extending the period by one duration each time.
	 *
	 * NOTE: Since 'has_user_level' excludes expired levels, an expired level cannot 
	 *       be renewed, instead it must be re-added using 'add_user_level'.
	 *       The (wanted) side-effect of this is that renewing before expiry maintains
	 *       the original start date, while re-adding changes the start date of the 
	 *       membership.
	 *
	 * @since  0.16.1-mattys101
	 * @param  int           $user_id
	 * @param  int           $level_id
	 * @param  boolean       $once_per_period (default: true)
	 * @return int|boolean
	 */
	public function renew_user_level($user_id, $level_id, $once_per_period=true) {
		if($this->has_user_level($user_id,$level_id)) {
			
			$renewed = false;
			$time = $this->get_user_level_start($user_id, $level_id);
			$renew_time = $this->get_user_level_renew($user_id, $level_id);
			
			// Only allow one renew per period
			if ($once_per_period && $renew_time && $renew_time > time()) {
				return false;
			}
			
			if ($renew_time && $renew_time > $time) {
				$time = $renew_time;
			}
			
			$duration = $this->metadata()->get('duration')->get_data($level_id);
			
			if( isset($duration['count'], $duration['unit']) && $time && $duration['count'] ) {
				$time = strtotime('+'.$duration['count'].' '.$duration['unit'], $time);
				$renewed = update_user_meta($user_id, RUA_App::META_PREFIX.'level_renew_'.$level_id, $time);
			}
			
			if ($renewed) {
				return $level_id;
			}
		}
		return false;
	}

	/**
	 * Remove level from user
	 *
	 * @since  0.3
	 * @param  $int    $user_id
	 * @param  $int    $level_id
	 * @return boolean
	 */
	public function remove_user_level($user_id,$level_id) {
		$this->reset_user_levels_caps( $user_id );
		return delete_user_meta($user_id,RUA_App::META_PREFIX.'level',$level_id) &&
			delete_user_meta($user_id,RUA_App::META_PREFIX.'level_'.$level_id) &&
			( delete_user_meta($user_id,RUA_App::META_PREFIX.'level_renew_'.$level_id) || true );
	}

	/**
	 * Get roles for specific user
	 * For internal use only
	 *
	 * @since  0.1
	 * @param  WP_User  $user
	 * @return array
	 */
	public function get_user_roles($user_id = null) {
		$roles = array();
		if(is_user_logged_in()) {
			if(!$user_id) {
				$user = wp_get_current_user();
			} else {
				$user = get_user_by('id',$user_id);
			}
			$roles = $user->roles;
			$roles[] = '-1'; //logged-in
		} else {
			$roles[] = '0'; //not logged-in
		}
		return $roles;
	}

	/**
	 * Check if user has level
	 *
	 * @since  0.6
	 * @param  int  $user_id
	 * @param  int  $level
	 * @return boolean
	 */
	public function has_user_level($user_id, $level) {
		return in_array($level, $this->get_user_levels($user_id,false,false));
	}

	/**
	 * Get user levels
	 * Traversed to their root
	 * Include levels synced with role
	 *
	 * @since  0.3
	 * @param  WP_User $user
	 * @param  boolean $hierarchical
	 * @param  boolean $synced_roles
	 * @param  boolean $include_expired
	 * @return array
	 */
	 public function get_user_levels(
	 	$user_id = null,
	 	$hierarchical = true,
	 	$synced_roles = true,
	 	$include_expired = false
	 	) {
		$all_levels = RUA_App::instance()->get_levels();
		$levels = array();
		if(!$user_id && is_user_logged_in()) {
			$user_id = wp_get_current_user();
			$user_id = $user_id->ID;
		}
		if($user_id) {
			$user_levels = get_user_meta($user_id, RUA_App::META_PREFIX.'level', false);
			foreach ($user_levels as $level) {
				//Only get user levels that are active
				if(isset($all_levels[$level]) && $all_levels[$level]->post_status == RUA_App::STATUS_ACTIVE) {
					if($include_expired || !$this->is_user_level_expired($user_id,$level)) {
						$levels[] = $level;
					}
				}
			}
		}
		if($synced_roles) {
			$user_roles = array_flip($this->get_user_roles($user_id));
			foreach ($all_levels as $level) {
				$synced_role = get_post_meta($level->ID,RUA_App::META_PREFIX.'role',true);
				if($synced_role !== '' && isset($user_roles[$synced_role])) {
					$levels[] = $level->ID;
				}
			}
		}
		if($hierarchical) {
			foreach($levels as $level) {
				$levels = array_merge($levels,get_post_ancestors((int)$level));
			}
		}
		update_postmeta_cache($levels);
		return $levels;
	}

	/**
	 * Get time of user level start
	 *
	 * @since  0.7
	 * @param  WP_User  $user
	 * @param  int      $level_id
	 * @return int
	 */
	public function get_user_level_start($user_id = null, $level_id) {
		if($user_id || is_user_logged_in()) {
			if(!$user_id) {
				$user_id = wp_get_current_user();
				$user_id = $user_id->ID;
			}
			return (int)get_user_meta($user_id,RUA_App::META_PREFIX.'level_'.$level_id,true);
		}
		return 0;
	}
	
	/**
	 * Get time of user level renewal (i.e. the time that the renewal 
	 * should start, not strictly the time that the renewal was performed).
	 *
	 * @since  0.16.1-mattys101
	 * @param  WP_User  $user
	 * @param  int      $level_id
	 * @return int
	 */
	public function get_user_level_renew($user_id = null, $level_id) {
		if($user_id || is_user_logged_in()) {
			if(!$user_id) {
				$user_id = wp_get_current_user();
				$user_id = $user_id->ID;
			}
			return (int)get_user_meta($user_id,RUA_App::META_PREFIX.'level_renew_'.$level_id,true);
		}
		return 0;
	}

	/**
	 * Get time of user level expiry.
	 *
	 * Since 0.16.1-mattys101, consideres the 'renew' time not just the 'start' time.
	 *
	 * @since  0.5
	 * @param  WP_User  $user
	 * @param  int      $level_id
	 * @return int
	 */
	public function get_user_level_expiry($user_id = null, $level_id) {
		if($user_id || is_user_logged_in()) {
			if(!$user_id) {
				$user_id = wp_get_current_user();
				$user_id = $user_id->ID;
			}
			$time = $this->get_user_level_start($user_id,$level_id);
			$renew_time = $this->get_user_level_renew($user_id,$level_id);
			$duration = $this->metadata()->get('duration')->get_data($level_id);
			
			if(isset($duration['count'],$duration['unit']) && $time && $duration['count']) {
				
				if ($renew_time && $renew_time > $time) {
					$time = $renew_time;
				}
				
				$time = strtotime('+'.$duration['count'].' '.$duration['unit']. ' 23:59',$time);
				
				return $time;
			}
		}
		return 0;
	}

	/**
	 * Check if user level is expired
	 *
	 * @since  0.5
	 * @param  WP_User  $user
	 * @param  int      $level_id
	 * @return boolean
	 */
	public function is_user_level_expired($user_id = null,$level_id) {
		$time_expire = $this->get_user_level_expiry($user_id,$level_id);
		return $time_expire && time() > $time_expire;
	}

	/**
	 * Check if current user has global access
	 *
	 * @since  0.6
	 * @param  WP_User  $user
	 * @return boolean
	 */
	public function _has_global_access($user = null) {
		if(is_user_logged_in() && !$user) {
			$user = wp_get_current_user();
		}
		$has_access = in_array('administrator',$this->get_user_roles());
		return apply_filters('rua/user/global-access', $has_access, $user);
	}

	/**
	 * Get conditional restrictions
	 * and authorize access for user
	 *
	 * @since  0.1
	 * @return void
	 */
	public function authorize_access() {

		if($this->_has_global_access()) {
			return;
		}

		$posts = WPCACore::get_posts(RUA_App::TYPE_RESTRICT);
		
		if ($posts) {
			$kick = 0;
			$levels = array_flip($this->get_user_levels());
			foreach ($posts as $post) {
				if(!isset($levels[$post->ID])) {
					$kick = $post->ID;
				} else {
					$kick = 0;
					break;
				}
			}

			if(!$kick && is_user_logged_in()) {
				$conditions = WPCACore::get_conditions(RUA_App::TYPE_RESTRICT);
				foreach ($conditions as $condition => $level) {
					//Check post type
					if(isset($posts[$level])) {
						$drip = get_post_meta($condition,RUA_App::META_PREFIX.'opt_drip',true);
						//Restrict access to dripped content
						if($drip && $this->metadata()->get('role')->get_data($level) === '') {
							$start = $this->get_user_level_start(null,$level);
							$drip_time = strtotime('+'.$drip.' days 00:00',$start);
							if(time() <= $drip_time) {
								$kick = $level;
							} else {
								$kick = 0;
								break;
							}
						} else {
							$kick = 0;
							break;
						}
					}
				}
			}

			if($kick) {
				$action = $this->metadata()->get('handle')->get_data($kick);
				self::$page = $this->metadata()->get('page')->get_data($kick);
				switch($action) {
					case 0:
						$redirect = '';
						$url = 'http'.( is_ssl() ? 's' : '' ).'://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
						if(is_numeric(self::$page)) {
							if(self::$page != get_the_ID()) {
								$redirect = get_permalink(self::$page);
							}
						} else {
							
							if($url != get_site_url().self::$page) {
								$redirect = get_site_url().self::$page;
							}
						}
						//only redirect if current page != redirect page
						if($redirect) {
							$url = remove_query_arg('redirect_to',urlencode($url));
							wp_safe_redirect(add_query_arg(
								'redirect_to',
								$url,
								$redirect
							));
							exit;
						}
						break;
					case 1:
						add_filter( 'the_content', array($this,'content_tease'), 8);
						break;
					default: break;
				}
				return;
			}
		}
	}

	/**
	 * Carry over page from restriction metadata
	 * @var integer
	 */
	public static $page = false;

	/**
	 * Limit content to only show teaser and
	 * page content from restriction metadata
	 *
	 * @since   0.1
	 * @param   string    $content
	 * @return  string
	 */
	public function content_tease( $content ) {
		if ( preg_match( '/(<span id="more-[0-9]*"><\/span>)/', $content, $matches ) ) {
			$teaser = explode($matches[0], $content, 2);
			$content = $teaser[0];
		} else {
			$content = '';
		}

		if(is_numeric(self::$page)) {
			setup_postdata(get_post(self::$page));
			$content .= get_the_content();
			wp_reset_postdata();
		}

		return $content;
	}

	/**
	 * Override user caps with level caps.
	 *
	 * @param  array   $allcaps
	 * @param  string  $cap
	 * @param  array   $args {
	 *     @type string  [0] Requested capability
	 *     @type int     [1] User ID
	 *     @type WP_User [2] Associated object ID (User object)
	 * }
	 * @param  WP_User $user
	 *
	 * @return array
	 */
	public function user_level_has_cap( $allcaps, $cap, $args, $user ) {
		$global_access = $this->_has_global_access();

		// if ($cap && $cap[0] == RUA_App::CAPABILITY && $global_access ) {
		// 	$allcaps[ $cap[0] ] = true;
		// }

		if( !$global_access && defined('WPCA_VERSION') ) {
			$allcaps = $this->get_user_levels_caps( $user->ID, $allcaps );
		}
		return $allcaps;
	}

	/**
	 * Get all user level capabilities (also checks hierarchy)
	 *
	 * @since  0.13
	 * @param  int    $user_id
	 * @param  array  $current_caps (optional preset)
	 * @return array
	 */
	public function get_user_levels_caps( $user_id, $current_caps = array() ) {
		if( ! isset( $this->user_levels_caps[ $user_id ] ) ) {
			$this->user_levels_caps[ $user_id ] = $current_caps;
			$levels = $this->get_user_levels( $user_id );
			if( $levels ) {
				$this->user_levels_caps[$user_id] = array_merge(
					$this->user_levels_caps[ $user_id ],
					//Make sure higher levels have priority
					//Side-effect: synced levels < normal levels
					$this->get_levels_caps( array_reverse( $levels ) )
				);
			}
		}
		return $this->user_levels_caps[$user_id];
	}

	/**
	 * Get all capabilities of one or multiple levels
	 *
	 * If you pass an array the order of these levels should be set correctly!
	 * The first level caps will be overwritten by the second etc.
	 *
	 * @since  0.13
	 * @param  array|int  $levels
	 * @return array
	 */
	public function get_levels_caps( $levels ) {
		$levels = (array) $levels;
		$caps = array();
		foreach ( $levels as $level ) {
			$level_caps = $this->metadata()->get('caps')->get_data( $level, true );
			foreach ( $level_caps as $key => $level_cap ) {
				$caps[$key] = !!$level_cap;
			}
		}
		return $caps;
	}

	/**
	 * Reset user level caps to trigger reload when `user_has_cap` filter is used.
	 *
	 * @since  0.16
	 * @param  $user_id
	 */
	public function reset_user_levels_caps( $user_id ) {
		unset( $this->user_levels_caps[ $user_id ] );
	}

	/**
	 * Maybe add level on user register
	 *
	 * @since  0.10
	 * @param  int  $user_id
	 * @return void
	 */
	public function registered_add_level($user_id) {
		$level_id = get_option('rua-registration-level',0);
		if($level_id) {
			$this->add_user_level($user_id,$level_id);
		}
	}
	
	/**
	 * Mediate file access, checking user levels.
	 *
	 * This method is based on the implementation provided by bueltge and 
	 * kraftner on Stackexchange: https://wordpress.stackexchange.com/a/37765
	 * 
	 * @since 0.17.2-mattys101
	 * @return void
	 */
	private function _authorize_file_access( $file ) {

		$file = preg_replace("/\.+/", '.', $file); // prevent '..'
		$parts = explode( '/', $file);
		$file = implode ('/', array_map('sanitize_file_name', $parts) ); // just to be safe
		
		$upload_dir = wp_upload_dir();
   		$path = $upload_dir[ 'basedir' ] . '/' . $file;
   		
   		if (!is_file($path)) {
   			// let it drop out to normal WP handling, which should result in 404.
   			// Not a huge fan of this, would prefer to make it more explicit
   			global $wp;
   			$wp->handle_404(); // should set up the state to be 404
   			return;
   		}
   		
   		if ($this->_has_global_access()) {
   			// Short cut for complete access
   			$this->_sendfile($path, $this->_determine_mimetype($path));
	    	die();
   		}
   		
        $mimetype = $this->_determine_mimetype($path);
   		$att_post = $this->_find_attachment_post($file, $mimetype);
        
        if (!$att_post) {
        	// most likely not a valid file, but drop out to WP 404, just to be safe
        	// this means we cannot accidentally serve files that have been manually placed 
        	// on the server but not through the proper WP mechanisms.  
        	global $wp;
   			$wp->handle_404(); // should set up the state to be 404
   			return;
        }
        
        // Check authorisation (provides the level, if any, that is blocking access)
        $level = $this->_access_blocked($att_post);
        
        // We also want to check the parent page of the attachment, so that if we lock 
        // down the parent page, we automatically lock down the attached files.
        // TODO: make this an option
        if (!$level && $att_post->post_parent) 
        	$level = $this->_access_blocked($att_post->post_parent);
        
        if ( $level ) {
        	// Always do redirect (the action, redirect or tease, doesn't matter here)
			$page = $this->metadata()->get('page')->get_data($level);
			$redirect = '';
			$url = 'http'.( is_ssl() ? 's' : '' ).'://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
			if (is_numeric($page)) {
				$redirect = get_permalink($page);
			} else if ($url != get_site_url() . $page) {
				$redirect = get_site_url() . $page;
			}
			//only redirect if current page != redirect page
			if($redirect) {
				$url = remove_query_arg('redirect_to',urlencode($url));
				wp_safe_redirect(add_query_arg(
					'redirect_to',
					$url,
					$redirect
				));
				exit();
			}
        }
        
        // Check standard 'password protection' using the parent post if available
        // (the attachment pages themselves cannot be given a password).
        // Placed this second as this would be how normal content would work, i.e. the 
        // template redirect would occur first, then you might see the password prompt.
        if ( $att_post->post_parent > 0 && post_password_required( $att_post->post_parent ) ) {
            wp_die( get_the_password_form() );// show the password form 
        }
        
        // We got this far, output the file.
        $this->_sendfile($path, $mimetype);
    	die();
	}
	
	/**
	 * Configures the response headers and puts the file content on the output stream.
	 */
	private function _sendfile($path, $mimetype) {
		header( 'Content-type: ' . $mimetype ); // always send this

	    $last_modified = gmdate( 'D, d M Y H:i:s', filemtime( $path ) );
		$etag = '"' . md5( $last_modified ) . '"';
		header( "Last-Modified: $last_modified GMT" );
		header( 'ETag: ' . $etag );
		header( 'Expires: ' . gmdate( 'D, d M Y H:i:s', time() + 100000000 ) . ' GMT' );
		
		// Support for Conditional GET
	    $this->_client_cache_control($last_modified, $etag);
		
		if ( false === strpos( $_SERVER['SERVER_SOFTWARE'], 'Microsoft-IIS' ) )
		    header( 'Content-Length: ' . filesize( $path ) );
	    
	    // TODO: support for gzip or deflate
//		header('Content-Encoding: identity');
	
		$bytes = @readfile( $path );
	}
	
	/**
	 * Finds the attachment post for the given file.
	 * Returns the post if found, FALSE otherwise.
	 */
	private function _find_attachment_post($file, $mimetype) {
       $att_posts = get_posts( array( 'post_type' => 'attachment', 'meta_query' => array( array( 'key' => '_wp_attached_file', 'value' => $file ) ) ) );
        
        if ( count($att_posts) > 0 ) {
        	// the file has an attachment page
        	return $att_posts[0];
        	// XXX: will there ever be a situation where there are multiple posts returned?
        }
        else if ( 0 === strpos($mimetype, 'image/') ) {
        	// images may have scaled thumbnails, we need to check if this is one of them.
            $file_info = pathinfo( $file );
            $filename = $file_info['filename'] . '.' . $file_info['extension'];
            $att_posts = get_posts( array( 'post_type' => 'attachment', 'meta_query' => array( array( 'key' => '_wp_attachment_metadata', 'compare' => 'LIKE', 'value' => $filename ) ) ) );
            foreach ( $att_posts as $SINGLEimage ) {
                $meta = wp_get_attachment_metadata( $SINGLEimage->ID );
               	
                if ( count($meta['sizes']) > 0 && $file_info['dirname'] == pathinfo($meta['file'])['dirname'] ) {
                    foreach ( $meta['sizes'] as $size ) {
                        if ( $filename == $size['file'] ) {
                        	return $SINGLEimage;
                        }
                    }
                }
            }
        }
        
        return false;
	}
	
	/**
	 * Return the mimetype of the file. Defaults to image if it cannot be properly identified.
	 */
	private function _determine_mimetype($file) {
		$mime = wp_check_filetype( $file );

		if( false === $mime[ 'type' ] && function_exists( 'mime_content_type' ) )
		    $mime[ 'type' ] = mime_content_type( $file );

		return $mime[ 'type' ]
				? $mime[ 'type' ]
				: 'image/' . substr( $file, strrpos( $file, '.' ) + 1 );
	}
	
	/**
	 * Respond with a 304 if the file has not been modified (according to client request).
	 */
	private function _client_cache_control($last_modified, $etag) {
		$client_etag = isset( $_SERVER['HTTP_IF_NONE_MATCH'] ) ? stripslashes( $_SERVER['HTTP_IF_NONE_MATCH'] ) : false;

		if( ! isset( $_SERVER['HTTP_IF_MODIFIED_SINCE'] ) )
		    $_SERVER['HTTP_IF_MODIFIED_SINCE'] = false;

		$client_last_modified = trim( $_SERVER['HTTP_IF_MODIFIED_SINCE'] );
		// If string is empty, return 0. If not, attempt to parse into a timestamp
		$client_modified_timestamp = $client_last_modified ? strtotime( $client_last_modified ) : 0;

		// Make a timestamp for our most recent modification...
		$modified_timestamp = strtotime($last_modified);

		if ( ( $client_last_modified && $client_etag )
		    ? ( ( $client_modified_timestamp >= $modified_timestamp) && ( $client_etag == $etag ) )
		    : ( ( $client_modified_timestamp >= $modified_timestamp) || ( $client_etag == $etag ) )
		    ) {
		    status_header( 304 );
		    exit();
		}
	}

}
//eol
