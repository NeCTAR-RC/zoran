from oslo_config import cfg

CONF = cfg.CONF


#
#  Nova settings
#
nova_group = cfg.OptGroup(name='nova',
                          title='Nova Options')
CONF.register_group(nova_group)

nova_tenant_opt = cfg.StrOpt(
    'admin_tenant_name',
    required=True,
    help='Tenant name')
CONF.register_opt(nova_tenant_opt, group=nova_group)

nova_user_opt = cfg.StrOpt(
    'admin_username',
    required=True,
    help='Openstack username')
CONF.register_opt(nova_user_opt, group=nova_group)

nova_password_opt = cfg.StrOpt(
    'admin_password',
    required=True,
    help='Password to connect Openstack with')
CONF.register_opt(nova_password_opt, group=nova_group)

nova_auth_url_opt = cfg.StrOpt(
    'auth_url',
    required=True,
    help='Keystone URL')
CONF.register_opt(nova_auth_url_opt, group=nova_group)

#
#  Email settings
#
email_group = cfg.OptGroup(name='email',
                           title='Email Options')
CONF.register_group(email_group)

email_report_subject_opt = cfg.StrOpt(
    'report_subject',
    required=True,
    default='ZORAN the protector report',
    help='Report email subject line.')
CONF.register_opt(email_report_subject_opt, group=email_group)

email_report_to_opt = cfg.StrOpt(
    'report_to',
    required=True,
    help='Report to address')
CONF.register_opt(email_report_to_opt, group=email_group)

email_report_from_opt = cfg.StrOpt(
    'report_from',
    required=True,
    help='Report from address')
CONF.register_opt(email_report_from_opt, group=email_group)

email_smtp_server_opt = cfg.StrOpt(
    'smtp_server',
    default='localhost',
    required=True,
    help='The hostname of the smtp server.')
CONF.register_opt(email_smtp_server_opt, group=email_group)


core_opts = [
    cfg.StrOpt('mongodb_connection',
               default='mongodb://localhost:27017/',
               help='The MongoDB connection string used to connect to the '
               'database',
               secret=True),
]

CONF.register_opts(core_opts)
