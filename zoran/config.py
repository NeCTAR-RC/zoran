from oslo.config import cfg

CONF = cfg.CONF

nova_group = cfg.OptGroup(name='nova',
                          title='Nova Options')
CONF.register_group(nova_group)

nova_tenant_opt = cfg.StrOpt('admin_tenant_name',
                             required=True,
                             help='Tenant name')
CONF.register_opt(nova_tenant_opt, group=nova_group)

nova_user_opt = cfg.StrOpt('admin_username',
                           required=True,
                           help='Openstack username')
CONF.register_opt(nova_user_opt, group=nova_group)

nova_password_opt = cfg.StrOpt('admin_password',
                               required=True,
                               help='Password to connect Openstack with')
CONF.register_opt(nova_password_opt, group=nova_group)

nova_auth_url_opt = cfg.StrOpt('auth_url',
                               required=True,
                               help='Keystone URL')
CONF.register_opt(nova_auth_url_opt, group=nova_group)


core_opts = [
    cfg.StrOpt('mongodb_connection',
               default='mongodb://localhost:27017/',
               help='The MongoDB connection string used to connect to the '
               'database',
               secret=True),
]

CONF.register_opts(core_opts)
