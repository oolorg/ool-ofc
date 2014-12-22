#!/usr/bin/env python
# -*- coding: utf-8 -*-


OFP_OFC_INSTANCE_NAME = 'ofp_ofc_instance_name'

FLOW_PRIORITY_DROP					= 200
FLOW_PRIORITY_PACKET_IN				= 400
FLOW_PRIORITY_PACKET_IN_DISABLE		= 600
FLOW_PRIORITY_FLOW					= 800

FLOW_IDLE_TIMEOUT_NORMAL				= 65535		# About 18hour.
FLOW_IDLE_TIMEOUT_PACKET_IN_DISABLE		= 60 * 10	# 10minutes
FLOW_IDLE_TIMEOUT_NO_LIMIT				= 0
FLOW_HARD_TIMEOUT_NO_LIMIT				= 0

HTTP_STATUS_SUCCESS			= 200
HTTP_STATUS_CREATED_SUCCESS	= 201
HTTP_STATUS_BAD_REQUEST		= 400
HTTP_STATUS_INTL_SRV_ERR	= 500

SUCCESS_MSG				= "Success"
ERR_MSG_BAD_REQUEST		= "Bad Request"
ERR_MSF_INT_SRV_ERR		= "Internal server error"

