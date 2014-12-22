import httplib2
import unirest

from common import log
from common import conf

LOG = log.getLogger(__name__)
CONF = conf.read_conf()

unirest.timeout(60)

class OfpmClient:

	def set_flow(self, dpid, inPort, srcMac, dstMac):
		dpidStr = (hex(dpid))
		header = {'Content-type':'application/json'}
		body = {'dpid':dpidStr[2:], 'inPort':inPort, 'srcMac':srcMac, 'dstMac':dstMac}
		LOG.debug("body = " + str(body))
		LOG.info("Request setFlow body = " + str(body))
		res = unirest.post(CONF.ofpm_set_flow_url, headers=header, params=str(body), callback=self.__http_response__)
		return 

	def init_flow(self, dpid):
		dpidStr = (hex(dpid))
		header = {'Content-type':'application/json'}
		body = {'datapathId':dpidStr[2:]}
		LOG.debug("body = " + str(body))
		LOG.info("Request initFlow body = " + str(body))
		res = unirest.post(CONF.ofpm_init_flow_url, headers=header, params=str(body), callback=self.__http_response__)
		return

	def set_desc_stats(self, dpid, descStats):
		header = {'Content-type':'application/json'}
		# LOG.info(descStats)
		res = unirest.post(CONF.ofpm_set_desc_stats_url, headers=header, params=str(descStats), callback=self.__http_response__)
		return 

	def set_port_stats(self, dpid, portStats):
		header = {'Content-type':'application/json'}
		# LOG.info("Request set_port_stats body = " + str(body))
		res = unirest.post(CONF.ofpm_set_port_stats_url, headers=header, params=str(portStats), callback=self.__http_response__)
		return 

	def set_port_desc_stats(self, dpid, portDescStats):
		header = {'Content-type':'application/json'}
		# LOG.info("Request set_port_desc_stats body = " + str(body))
		res = unirest.post(CONF.ofpm_set_desc_port_stats_url, headers=header, params=str(portDescStats), callback=self.__http_response__)
		return 

	def set_flow_stats(self, dpid, flowStats):
		header = {'Content-type':'application/json'}
		# LOG.info("Request set_flow_stats body = " + str(body))
		res = unirest.post(CONF.ofpm_set_flow_stats_url, headers=header, params=str(flowStats), callback=self.__http_response__)
		return

	def __http_request__(self, url, method, header, body=None):
		LOG.debug("START")
		LOG.debug("url = " + url + ", method = " + method + ", header = " + str(header) + ", body = " + str(body))

		resp, content = httplib2.Http().request(url, method, headers=header, body=body)
		LOG.info("Request Result = %s", str(content))
		LOG.debug("END")
		return resp, content

	def __http_response__(self, res):
		LOG.debug("START")
		LOG.info("Response status = " + str(res.code) + ", body = " + str(res.body))
		LOG.debug("END")
