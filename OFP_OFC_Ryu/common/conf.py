#!/usr/bin/env python
# -*- coding: utf-8 -*-

from oslo.config import cfg

LOG_DIR = '/var/log/ool-ofp-ofc'
LOG_FILE_NAME = 'ofc.log'

CONF_DIR = 'conf'
CONF_FILE = CONF_DIR + '/' + 'ofp-ofc.conf'

SERVICE_URL = '/ofc/ryu/ctrl'

ofp_ofc_config = None

def read_conf():
	global ofp_ofc_config

	if not ofp_ofc_config:
		ool_ofc_opts = [
			cfg.StrOpt('logging_default_format_string',
						default='%(asctime)s %(process)d %(funcName)s %(filename)s:%(lineno)d [%(levelname)s] '
						'%(message)s'),
			cfg.StrOpt('logging_debug_format_suffix',
						default=''),
			cfg.BoolOpt('debug',default='True'),
			cfg.StrOpt('log_dir',default=LOG_DIR),
			cfg.StrOpt('log_file',default=LOG_FILE_NAME),
			cfg.StrOpt('logging_level',default='debug'),

			cfg.StrOpt('service_url', default=SERVICE_URL),
			cfg.StrOpt('desc_stats_request_url', default=SERVICE_URL + '/desc_stats'),
			cfg.StrOpt('port_stats_request_url', default=SERVICE_URL + '/port_stats'),
			cfg.StrOpt('port_desc_stats_request_url', default=SERVICE_URL + '/port_desc_stats'),
			cfg.StrOpt('flow_stats_request_url', default=SERVICE_URL + '/flow_stats'),

			cfg.StrOpt('ofpm_set_flow_url', default='http://172.16.1.84:18080/ofpm/logical_topology/setFlow'),
			cfg.StrOpt('ofpm_init_flow_url', default='http://172.16.1.84:18080/ofpm/logical_topology/initFlow'),
			cfg.StrOpt('ofpm_set_desc_stats_url', default='http://172.16.1.84:8000/ofpm/stats/set_desc_stats'),
			cfg.StrOpt('ofpm_set_port_stats_url', default='http://172.16.1.84:8000/ofpm/stats/set_port_stats'),
			cfg.StrOpt('ofpm_set_desc_port_stats_url', default='http://172.16.1.84:8000/ofpm/stats/set_port_desc_stats'),
			cfg.StrOpt('ofpm_set_flow_stats_url', default='http://172.16.1.84:8000/ofpm/stats/set_flow_stats'),

		]

		ofp_ofc_config = cfg.ConfigOpts()
		ofp_ofc_config.register_cli_opts(ool_ofc_opts)
		print CONF_FILE
		ofp_ofc_config(['--config-file', CONF_FILE, '--config-dir', CONF_DIR])
		print '===================LOADING CONFIG====================='
		for k, v in ofp_ofc_config.items():
			print '%s = %s' % (str(k), str(v))
		print '===================LOADING CONFIG====================='

	return ofp_ofc_config
