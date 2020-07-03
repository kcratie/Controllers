from ryu import cfg

CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.StrOpt("config-file", default=None,
               help="Fully qualified name of the configuration file"),
    cfg.StrOpt("config-string", default=None,
               help="Configuration as a JSON string"),], group="bf")
