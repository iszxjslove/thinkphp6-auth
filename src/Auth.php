<?php
// +----------------------------------------------------------------------
// | ThinkPHP 6.0 auth
// +----------------------------------------------------------------------
// | Copyright (c) 2018 http://www.wyxgn.com All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 ;)
// +----------------------------------------------------------------------
// | Author: lqsong <228762287@qq.com>
// +----------------------------------------------------------------------
namespace think\iszxjslove;

use think\db\exception\DataNotFoundException;
use think\db\exception\DbException;
use think\db\exception\ModelNotFoundException;
use think\facade\Db;
use think\facade\Config;
use think\facade\Session;
use think\facade\Request;
use think\Model;

/**
 * 权限认证类
 * 功能特性：
 * 1，是对规则进行认证，不是对节点进行认证。用户可以把节点当作规则名称实现对节点进行认证。
 *      $auth=new Auth();  $auth->check('规则名称','用户id')
 * 2，可以同时对多条规则进行认证，并设置多条规则的关系（or或者and）
 *      $auth=new Auth();  $auth->check('规则1,规则2','用户id','and')
 *      第三个参数为and时表示，用户需要同时具有规则1和规则2的权限。 当第三个参数为or时，表示用户值需要具备其中一个条件即可。默认为or
 * 3，一个用户可以属于多个用户组(auth_group_access表 定义了用户所属用户组)。我们需要设置每个用户组拥有哪些规则(auth_group 定义了用户组权限)
 *
 * 4，支持规则表达式。
 *      在auth_rule 表中定义一条规则时，如果type为1， condition字段就可以定义规则表达式。 如定义{score}>5  and {score}<100  表示用户的分数在5-100之间时这条规则才会通过。
 */
//数据库 请手动创建下sql
/*
------------------------------
-- think_auth_rule，规则表，
-- id:主键，name：规则唯一标识, title：规则中文名称 status 状态：为1正常，为0禁用，condition：规则表达式，为空表示存在就验证，不为空表示按照条件验证
------------------------------
 DROP TABLE IF EXISTS `think_auth_rule`;
CREATE TABLE `think_auth_rule` (
    `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
    `name` char(80) NOT NULL DEFAULT '',
    `title` char(20) NOT NULL DEFAULT '',
    `status` tinyint(1) NOT NULL DEFAULT '1',
    `condition` char(100) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8;
------------------------------
-- think_auth_group 用户组表，
-- id：主键， title:用户组中文名称， rules：用户组拥有的规则id， 多个规则","隔开，status 状态：为1正常，为0禁用
------------------------------
 DROP TABLE IF EXISTS `think_auth_group`;
CREATE TABLE `think_auth_group` (
    `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
    `title` char(100) NOT NULL DEFAULT '',
    `status` tinyint(1) NOT NULL DEFAULT '1',
    `rules` char(80) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8;
------------------------------
-- think_auth_group_access 用户组明细表
-- uid:用户id，group_id：用户组id
------------------------------
DROP TABLE IF EXISTS `think_auth_group_access`;
CREATE TABLE `think_auth_group_access` (
    `uid` mediumint(8) unsigned NOT NULL,
    `group_id` mediumint(8) unsigned NOT NULL,
    UNIQUE KEY `uid_group_id` (`uid`,`group_id`),
    KEY `uid` (`uid`),
    KEY `group_id` (`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
*/

class Auth
{
    /**
     * var object 对象实例
     */
    protected static $_instance;

    //默认配置
    protected $config = [
        'auth_on'               => 1,                   // 权限开关
        'auth_type'             => 1,                   // 认证方式，1为实时认证；2为登录认证。
        'auth_platform'         => '',                  // 平台
        'auth_group'            => 'auth_group',        // 用户组数据表名
        'auth_group_access'     => 'auth_group_access', // 用户-用户组关系表
        'auth_rule'             => 'auth_rule',         // 权限规则表
        'auth_user'             => 'auth_user',         // 用户信息表
        'access_table_group_id' => 'auth_group_id',     // 关系表组ID
        'access_table_user_id'  => 'user_id',           // 关系表用户ID
    ];

    protected $group_pk = '';

    protected $rule_pk = '';

    protected $user_pk = '';

    protected $access_table_group_id = '';

    protected $access_table_user_id = '';

    /**
     * 类架构函数
     * Auth constructor.
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        //可设置配置项 auth, 此配置项为数组。
        if ($auth = Config::get('auth')) {
            $options = array_merge($auth, $options);
        }
        $this->config = array_merge($this->config, $options);
        $this->setGroupPk();
        $this->setRulePk();
        $this->setUserPk();
        $this->setAccessTableGroupId();
        $this->setAccessTableUserId();
    }

    protected function setGroupPk()
    {
        $this->group_pk = $this->getTablePk($this->config['auth_group'], 'id');
    }

    protected function setRulePk()
    {
        $this->rule_pk = $this->getTablePk($this->config['auth_rule'], 'id');
    }

    protected function setUserPk()
    {
        $this->user_pk = $this->getTablePk($this->config['auth_user'], 'id');
    }

    protected function setAccessTableGroupId()
    {
        $groupPk = $this->group_pk === $this->user_pk ? 'auth_group_' . $this->group_pk : $this->group_pk;
        $this->access_table_group_id = $this->config['access_table_group_id'] ?: $groupPk;
    }

    protected function setAccessTableUserId()
    {
        $userPk = $this->group_pk === $this->user_pk ? 'user_' . $this->user_pk : $this->user_pk;
        $this->access_table_user_id = $this->config['access_table_user_id'] ?: $userPk;
    }

    /**
     * 获取表主键
     * @param $tableName
     * @param string $default
     * @return mixed|string
     */
    protected function getTablePk($tableName, $default = '')
    {
        $table = Db::name($tableName);
        $pk = $table->getPk();
        return is_string($pk) ? $pk : $default;
    }

    /**
     * 初始化
     * @param array $options
     * @return static
     */
    public static function instance(array $options = [])
    {
        if (is_null(self::$_instance)) {
            self::$_instance = new static($options);
        }
        return self::$_instance;
    }

    /**
     * 检查权限
     * @param $name string|array  需要验证的规则列表,支持逗号分隔的权限规则或索引数组
     * @param $uid  int           认证用户的id
     * @param int $type 认证类型
     * @param string $mode 执行check的模式
     * @param string $relation 如果为 'or' 表示满足任一条规则即通过验证;如果为 'and'则表示需满足所有规则才能通过验证
     * @return bool 通过验证返回true;失败返回false
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
     */
    public function check(array $name, $uid, $type = 1, $mode = 'url', $relation = 'or')
    {
        if (!$this->config['auth_on']) {
            return true;
        }
        // 获取用户需要验证的所有有效规则列表
        $authList = $this->getAuthList($uid, $type);
        if (is_string($name)) {
            $name = strtolower($name);
            if (strpos($name, ',') !== false) {
                $name = explode(',', $name);
            } else {
                $name = [$name];
            }
        }
        $list = []; //保存验证通过的规则名
        $REQUEST = [];
        if ('url' === $mode) {
            $REQUEST = unserialize(strtolower(serialize(Request::param())), '');
        }
        foreach ($authList as $auth) {
            $query = preg_replace('/^.+\?/U', '', $auth);
            if ('url' === $mode && $query !== $auth) {
                parse_str($query, $param); //解析规则中的param
                $intersect = array_intersect_assoc($REQUEST, $param);
                $auth = preg_replace('/\?.*$/U', '', $auth);
                if ($intersect === $param && in_array($auth, $name, true)) {
                    //如果节点相符且url参数满足
                    $list[] = $auth;
                }
            } else {
                if (in_array($auth, $name, true)) {
                    $list[] = $auth;
                }
            }
        }
        if ('or' === $relation && !empty($list)) {
            return true;
        }
        $diff = array_diff($name, $list);
        return 'and' === $relation && empty($diff);
    }

    /**
     * 根据用户id获取用户组,返回值为数组
     * @param  $uid int     用户id
     * return array       用户所属的用户组 array(
     *     array('uid'=>'用户id','group_id'=>'用户组id','title'=>'用户组名称','rules'=>'用户组拥有的规则id,多个,号隔开'),
     *     ...)
     * @return array|mixed|\think\Collection
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
     */
    public function getGroups($uid)
    {
        static $groups = [];
        if (isset($groups[$uid])) {
            return $groups[$uid];
        }
        // 转换表名
        $auth_group_access = $this->config['auth_group_access'];
        $auth_group = $this->config['auth_group'];
        // 执行查询
        $user_groups = Db::view($auth_group_access, "{$this->access_table_user_id},{$this->access_table_group_id}")
            ->view($auth_group, 'title,rules', "{$auth_group_access}.{$this->access_table_group_id}={$auth_group}.{$this->group_pk}", 'LEFT')
            ->where("{$auth_group_access}.{$this->access_table_user_id}='{$uid}' and {$auth_group}.status='1'")
            ->select();
        $groups[$uid] = $user_groups ?: [];
        return $groups[$uid];
    }

    /**
     * 获得权限列表
     * @param $uid
     * @param $type
     * @return array|mixed
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
     */
    protected function getAuthList($uid, $type)
    {
        static $_authList = []; //保存用户验证通过的权限列表
        $uType = $uid . implode(',', (array)$type);
        if (isset($_authList[$uType])) {
            return $_authList[$uType];
        }
        if (2 === (int)$this->config['auth_type'] && Session::has('_auth_list_' . $uType)) {
            return Session::get('_auth_list_' . $uType);
        }
        //读取用户所属用户组
        $groups = $this->getGroups($uid);
        $ids = []; //保存用户所属用户组设置的所有权限规则id
        foreach ($groups as $g) {
            $ids[] = explode(',', trim($g['rules'], ','));
        }
        $ids = array_unique(array_merge(...$ids));
        if (empty($ids)) {
            $_authList[$uType] = [];
            return [];
        }
        $map = [
            ['type', '=', $type],
            ['id', 'in', $ids],
            //['status','=',1],
        ];
        //读取用户组所有权限规则
        $rules = Db::name($this->config['auth_rule'])->where($map)->field('condition,name')->select();
        //循环规则，判断结果。
        $authList = []; //
        foreach ($rules as $rule) {
            if (!empty($rule['condition'])) {
                //根据condition进行验证
                $user = $this->getUserInfo($uid); //获取用户信息,一维数组
                $command = preg_replace('/{(\w*?)}/', '$user[\'$1\']', $rule['condition']);
                $condition = false;
                @(eval('$condition=(' . $command . ');'));
                if ($condition) {
                    $authList[] = strtolower($rule['name']);
                }
            } else {
                //只要存在就记录
                $authList[] = strtolower($rule['name']);
            }
        }
        $_authList[$uType] = $authList;
        if (2 === (int)$this->config['auth_type']) {
            //规则列表结果保存到session
            Session::set('_auth_list_' . $uType, $authList);
        }
        return array_unique($authList);
    }

    /**
     * 获得用户资料,根据自己的情况读取数据库
     * @param $uid
     * @return array|Model|null
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
     */
    public function getUserInfo($uid)
    {
        static $userinfo = [];
        $user = Db::name($this->config['auth_user']);
        if (!isset($userinfo[$uid])) {
            $userinfo[$uid] = $user->where($this->user_pk, $uid)->find();
        }
        return $userinfo[$uid];
    }

    /**
     * 根据uid获取角色名称
     * @param $uid
     * @return false|mixed
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
     */
    public function getRole($uid)
    {
        $groupAccess = Db::name($this->config['auth_group_access'])->where($this->access_table_user_id, $uid)->find();
        if (!$groupAccess || !isset($groupAccess[$this->access_table_group_id])) {
            return false;
        }
        $group = Db::name($this->config['auth_group'])->where($this->group_pk, $groupAccess[$this->access_table_group_id])->find();
        if (!$group) {
            return false;
        }
        return $group->title;
    }

    /**
     * 授予用户权限
     * @param $uid
     * @param $group_id
     * @return int
     * @throws DbException
     */
    public function setRole($uid, $group_id): int
    {
        return Db::name('auth_group_access')
            ->where($this->access_table_user_id, $uid)
            ->update([$this->access_table_group_id => $group_id]);
    }
}