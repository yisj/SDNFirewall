#!/usr/bin/python
# CS 6250 Fall 2025 - SDN Firewall Project with POX
# build gibson-29

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr
# 주의: IP 주소는 CIDR 문자열 그대로 넘깁니다 (IPAddr()로 감싸지 않음)

log = core.getLogger()

# 우선순위: Allow가 Block을 반드시 이겨야 함
PRIO_BLOCK = 1
PRIO_ALLOW = 20000

DL_TYPE_IPV4 = 0x0800
IPPROTO_TCP = 6
IPPROTO_UDP = 17

def _is_used(val: str) -> bool:
    """'-' 가 아닌 실제 값인지 확인"""
    return val is not None and val != '-'

def _to_int(val: str):
    """정수필드 변환 (이미 검증됨을 가정). 사용 안하면 None."""
    return int(val) if _is_used(val) else None

def _to_ethaddr(val: str):
    """MAC 문자열을 EthAddr로 변환"""
    return EthAddr(val) if _is_used(val) else None

def _needs_ipv4(policy: dict) -> bool:
    """
    IPv4 dl_type 세팅이 필요한지 판단.
    - ip-src / ip-dst / ipprotocol / (TCP/UDP 포트)이 지정되면 필요.
    """
    if _is_used(policy['ip-src']) or _is_used(policy['ip-dst']):
        return True
    if _is_used(policy['ipprotocol']):
        return True
    # 포트가 언급되었다면 TCP/UDP 전제이므로 IPv4 필요
    if _is_used(policy['port-src']) or _is_used(policy['port-dst']):
        return True
    return False

def _should_set_ports(ipproto: int) -> bool:
    """포트 매칭은 TCP/UDP일 때만 세팅"""
    return ipproto in (IPPROTO_TCP, IPPROTO_UDP)

def firewall_policy_processing(policies):
    '''
    configure.pol에서 읽어온 policy(dict)들을 바탕으로
    OpenFlow flow_mod 객체들을 생성하여 반환합니다.
    - Allow 규칙: 높은 priority + OFPP_NORMAL 출력 액션
    - Block 규칙: 매치 후 액션 없이 drop
    - 매치 필드는 '-' 는 절대 세팅하지 않음
    - 포트 매칭 시 반드시 TCP/UDP 및 IPv4 선행 조건 충족
    '''
    rules = []

    for policy in policies:
        action_str = policy['action']             # 'Allow' or 'Block'
        mac_src     = _to_ethaddr(policy['mac-src'])
        mac_dst     = _to_ethaddr(policy['mac-dst'])
        ip_src_cidr = policy['ip-src'] if _is_used(policy['ip-src']) else None
        ip_dst_cidr = policy['ip-dst'] if _is_used(policy['ip-dst']) else None
        ipproto     = _to_int(policy['ipprotocol']) if _is_used(policy['ipprotocol']) else None
        tp_src      = _to_int(policy['port-src']) if _is_used(policy['port-src']) else None
        tp_dst      = _to_int(policy['port-dst']) if _is_used(policy['port-dst']) else None

        # flow_mod 생성
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match()

        # 우선순위 설정 (Allow > Block)
        if action_str == 'Allow':
            fm.priority = PRIO_ALLOW
        else:
            fm.priority = PRIO_BLOCK  # 'Block'

        # L2 매치 (MAC)
        if mac_src is not None:
            fm.match.dl_src = mac_src
        if mac_dst is not None:
            fm.match.dl_dst = mac_dst

        # IPv4 필요 여부 판단
        if _needs_ipv4(policy):
            fm.match.dl_type = DL_TYPE_IPV4

        # L3 매치 (IP CIDR 문자열 그대로)
        if ip_src_cidr is not None:
            fm.match.nw_src = ip_src_cidr
        if ip_dst_cidr is not None:
            fm.match.nw_dst = ip_dst_cidr

        # L3 프로토콜 (ICMP=1, TCP=6, UDP=17, 기타도 허용)
        if ipproto is not None:
            fm.match.nw_proto = ipproto

        # L4 포트 매치 (TCP/UDP일 때만)
        if ipproto is not None and _should_set_ports(ipproto):
            if tp_src is not None:
                fm.match.tp_src = tp_src
            if tp_dst is not None:
                fm.match.tp_dst = tp_dst
        else:
            # 포트가 지정돼도 ipprotocol이 TCP/UDP가 아니면 세팅하지 않음
            # (POX의 "Fields ignored due to unspecified prerequisites" 경고 회피)
            pass

        # 액션: Allow면 정상 포워딩, Block이면 드롭(액션 없음)
        if action_str == 'Allow':
            fm.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))

        # 디버그 로그 (원형 출력은 과할 수 있어 간단하게)
        print('Added Rule', policy['rulenum'], ':', policy['comment'])
        rules.append(fm)

    return rules