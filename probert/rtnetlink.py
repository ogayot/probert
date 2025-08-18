# Copyright 2025 Canonical, Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" This module is a pyroute2-based rewrite of _rtnetlinkmodule.c (which was a
C implementation using libnl).
"""

import abc
import collections
import dataclasses
import enum
import ipaddress
import typing

import pyroute2
from pyroute2.netlink import nlmsg

# In the cache, we store the whole netlink message.
# But only the relevant fields are checked for "equality".
CacheEntry = nlmsg


class EventData:
    """When creating an event for the observer, use these functions to generate
    the data."""
    @staticmethod
    def build_link_event_data(msg: nlmsg) -> dict[str, typing.Any]:
        link_info = msg.get_attr("IFLA_LINKINFO")
        if link_info:
            is_vlan = link_info.get_attr("IFLA_INFO_KIND") == "vlan"
        else:
            is_vlan = False
        data = {
            "ifindex": msg["index"],
            "flags": msg["flags"],
            "arptype": msg["ifi_type"],
            "family": msg["family"],
            "is_vlan": is_vlan,
            "name": msg.get_attr("IFLA_IFNAME").encode("utf-8"),
        }
        if data["is_vlan"]:
            data["vlan_id"] = link_info.get_attr(
                "IFLA_INFO_DATA").get_attr("IFLA_VLAN_ID")
            data["vlan_link"] = msg.get_attr("IFLA_LINK")
        return data

    @staticmethod
    def build_addr_event_data(msg: nlmsg) -> dict[str, typing.Any]:
        data = {
            "ifindex": msg["index"],
            # msg["flags"] (i.e., ifaddrmsg.ifa_flags) is a 8-bits integer and
            # can only store some of the flags. The, IFA_FLAGS attribute is an
            # extension that supports 32-bits flags.
            # See rtnetlink (7)
            "flags": msg.get_attr("IFA_FLAGS", msg["flags"]),
            "family": msg["family"],
            "scope": msg["scope"],
        }

        # * For IPv4, the local address is stored in IFA_LOCAL.
        # * For IPv6, the local address is in IFA_ADDRESS and IFA_LOCAL does
        # not exist.
        # See libnl implementation for details.
        local_addr = msg.get_attr("IFA_LOCAL", msg.get_attr("IFA_ADDRESS"))
        pfxlen = msg["prefixlen"]
        if_local_addr = ipaddress.ip_interface(f"{local_addr}/{pfxlen}")
        if if_local_addr.max_prefixlen == pfxlen:
            local_addr = if_local_addr.ip.compressed
        else:
            local_addr = if_local_addr.compressed
        # For some reason, probert uses decode("latin-1") so let's comply
        # ...
        data["local"] = local_addr.encode("latin-1")

        return data

    @staticmethod
    def build_route_event_data(msg: nlmsg) -> dict[str, typing.Any]:
        if not msg["dst_len"]:
            dst = "default"
        else:
            addr = msg.get_attr("RTA_DST")
            pfxlen = msg["dst_len"]
            network = ipaddress.ip_network(f"{addr}/{pfxlen}")
            if network.max_prefixlen == pfxlen:
                dst = network.network_address.compressed
            else:
                dst = network.compressed
        return {
            "family": msg["family"],
            "type": msg["type"],
            "table": msg["table"],
            "dst": dst.encode("utf-8"),
            "ifindex": msg.get_attr("RTA_OIF"),
        }


class CacheEntryComparer:
    """Helpers to compare the content of two entries from the cache."""
    @staticmethod
    def direct(name: str):
        def inner(evt):
            return evt[name]
        return inner

    @staticmethod
    def attr(name: str):
        def inner(evt):
            return evt.get_attr(name)
        return inner

    @staticmethod
    def nested_attr(names: list[str]):
        def inner(evt):
            v = evt
            for name in names:
                v = v.get_attr(name)
                if v is None:
                    return None
            return v
        return inner

    @staticmethod
    def are_equal(
            entry_a: CacheEntry, entry_b: CacheEntry, *,
            fields: list[typing.Callable[[CacheEntry], bool]]) -> bool:
        for attr_cb in fields:
            if attr_cb(entry_a) != attr_cb(entry_b):
                return False
        return True


class Cache(collections.UserDict, abc.ABC):
    @dataclasses.dataclass(frozen=True)
    class UniqueIdentifier(abc.ABC):
        @classmethod
        @abc.abstractmethod
        def from_nl_msg(cls, msg: nlmsg) -> "Cache.UniqueIdentifier":
            raise NotImplementedError

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    @abc.abstractmethod
    def are_entries_equal(a: CacheEntry, b: CacheEntry) -> bool:
        raise NotImplementedError


class LinkCache(Cache):
    @dataclasses.dataclass(frozen=True)
    class UniqueIdentifier:
        """How to uniquely identify a link. This class is used as the key in
        the link cache.
        For more information, see in libnl:
            .oo_id_attrs = LINK_ATTR_IFINDEX | LINK_ATTR_FAMILY
        """
        ifindex: int
        family: int

        @classmethod
        def from_nl_msg(cls, msg: nlmsg) -> "LinkCache.UniqueIdentifier":
            return cls(ifindex=msg["index"], family=msg["family"])

    @staticmethod
    def are_entries_equal(a: CacheEntry, b: CacheEntry) -> bool:
        fields_to_compare = [
            CacheEntryComparer.direct("index"),
            CacheEntryComparer.attr("IFLA_MTU"),
            CacheEntryComparer.attr("IFLA_LINK"),
            CacheEntryComparer.attr("IFLA_LINK_NETNSID"),
            CacheEntryComparer.attr("IFLA_TXQLEN"),
            CacheEntryComparer.attr("IFLA_WEIGHT"),
            CacheEntryComparer.attr("IFLA_MASTER"),
            CacheEntryComparer.direct("family"),
            CacheEntryComparer.attr("IFLA_LINKMODE"),
            CacheEntryComparer.attr("IFLA_QDISC"),
            CacheEntryComparer.attr("IFLA_IFNAME"),
            CacheEntryComparer.attr("IFLA_ADDRESS"),
            CacheEntryComparer.attr("IFLA_BROADCAST"),
            CacheEntryComparer.attr("IFLA_IFALIAS"),
            CacheEntryComparer.attr("IFLA_NUM_VF"),
            CacheEntryComparer.attr("IFLA_PROMISCUITY"),
            CacheEntryComparer.attr("IFLA_NUM_TX_QUEUES"),
            CacheEntryComparer.attr("IFLA_NUM_RX_QUEUES"),
            CacheEntryComparer.direct("flags"),
            # TODO protinfo
            # TODO infodata
        ]
        return CacheEntryComparer.are_equal(a, b, fields=fields_to_compare)


class AddrCache(Cache):
    @dataclasses.dataclass(frozen=True)
    class UniqueIdentifier:
        """How to uniquely identify an address. This class is used as the key
        in the addr cache.
        For more information, see in libnl:
            .oo_id_attrs_get = addr_id_attrs_get,
            .oo_id_attrs     = (ADDR_ATTR_FAMILY | ADDR_ATTR_IFINDEX |
                                ADDR_ATTR_LOCAL | ADDR_ATTR_PREFIXLEN)
        """
        ifindex: int
        family: int
        prefixlen: int
        # In theory we want: local and optionally peer (depending on family)
        # But let's just include IFA_ADDRESS, IFA_LOCAL
        ifa_local: str | None
        ifa_address: str | None

        @classmethod
        def from_nl_msg(cls, msg: nlmsg) -> "AddrCache.UniqueIdentifier":
            return cls(
                ifindex=msg["index"],
                family=msg["family"],
                prefixlen=msg["prefixlen"],
                ifa_address=msg.get_attr("IFA_ADDRESS"),
                ifa_local=msg.get_attr("IFA_LOCAL"),
            )

    @staticmethod
    def are_entries_equal(a: CacheEntry, b: CacheEntry) -> bool:
        fields_to_compare = [
            CacheEntryComparer.direct("index"),
            CacheEntryComparer.direct("family"),
            CacheEntryComparer.direct("scope"),
            CacheEntryComparer.direct("label"),
            CacheEntryComparer.attr("IFA_LABEL"),
            # local (and peer) addresses.
            CacheEntryComparer.direct("prefixlen"),
            CacheEntryComparer.attr("IFA_ADDRESS"),
            CacheEntryComparer.attr("IFA_LOCAL"),
            CacheEntryComparer.attr("IFA_MULTICAST"),
            CacheEntryComparer.attr("IFA_BROADCAST"),
            CacheEntryComparer.attr("IFA_ANYCAST"),
            CacheEntryComparer.attr("IFA_CACHEINFO"),
            # flags (IFA_FLAGS is a 32-bits extension)
            CacheEntryComparer.direct("flags"),
            CacheEntryComparer.attr("IFA_FLAGS"),
        ]
        return CacheEntryComparer.are_equal(a, b, fields=fields_to_compare)


class RouteCache(Cache):
    @dataclasses.dataclass(frozen=True)
    class UniqueIdentifier:
        """How to uniquely identify a route. This class is used as the key in
        the route cache.
        For more information, see in libnl:
            .oo_id_attrs = (ROUTE_ATTR_FAMILY | ROUTE_ATTR_TOS |
                            ROUTE_ATTR_TABLE | ROUTE_ATTR_DST |
                            ROUTE_ATTR_PRIO),
            .oo_id_attrs_get        = route_id_attrs_get
        """
        family: int
        tos: int
        table: int
        dst: str | None
        prio: int | None    # None for MPLS
        # NOTE: Multiple special routes (e.g. multicast routes) can have the
        # same destination address but a different output interface (i.e.,
        # RTA_OIF). They should probably not be considered the same route (and
        # therefore RTA_OIF should probably be part of the unique identifier).
        # But our previous implementation based on libnl didn't have that
        # today so we're mimicking the behavior.
        # As a result, in the example below, the second route might potentially
        # be discarded since the two routes have the same unique identifier.
        # $ ip -6 route show table 255
        # multicast ff00::/8 dev lxdbr0 proto kernel metric 256 pref medium
        # multicast ff00::/8 dev dummy2 proto kernel metric 256 pref medium

        @classmethod
        def from_nl_msg(cls, msg: nlmsg) -> "RouteCache.UniqueIdentifier":
            return cls(
                family=msg["family"],
                tos=msg["tos"],
                table=msg["table"],
                dst=msg.get_attr("RTA_DST"),
                prio=msg.get_attr("RTA_PRIORITY"),
            )

    @staticmethod
    def are_entries_equal(a: CacheEntry, b: CacheEntry) -> bool:
        fields_to_compare = [
            CacheEntryComparer.direct("family"),
            CacheEntryComparer.direct("tos"),
            CacheEntryComparer.direct("table"),
            CacheEntryComparer.direct("proto"),
            CacheEntryComparer.direct("scope"),
            CacheEntryComparer.direct("type"),
            CacheEntryComparer.attr("RTA_PRIORITY"),
            CacheEntryComparer.attr("RTA_DST"),
            CacheEntryComparer.attr("RTA_SRC"),
            CacheEntryComparer.attr("RTA_IIF"),
            CacheEntryComparer.attr("RTA_PREFSRC"),
            CacheEntryComparer.attr("RTA_TTL_PROPAGATE"),
            # TODO There is more to do here! lib/route/route_obj.c /
            # route_compare
        ]
        return CacheEntryComparer.are_equal(a, b, fields=fields_to_compare)


class EventResult(enum.StrEnum):
    """Enumerates the different outcomes that an event can produce."""
    NEW = "NEW"            # Send a NEW event to the observer
    CHANGE = "CHANGE"      # Send a CHANGE event to the observer
    DEL = "DEL"            # Send a DEL event to the observer

    DISCARD = enum.auto()  # Do not send any event to the observer


class Listener:
    @dataclasses.dataclass
    class MsgHandler:
        new: str
        cache: Cache
        observer_callback: typing.Callable[[str, dict[str, typing.Any]], None]
        build_event_data: typing.Callable[[nlmsg], dict[str, typing.Any]]

        def cache_handle_nl_msg(self, msg: nlmsg) -> EventResult:
            identifier = self.cache.UniqueIdentifier.from_nl_msg(msg)
            if msg["event"] == self.new:
                if identifier not in self.cache:
                    self.cache[identifier] = msg
                    return EventResult.NEW

                if self.cache.are_entries_equal(self.cache[identifier], msg):
                    # We still update the cache. Values are not necessarily
                    # meanningful but they are more up to date.
                    self.cache[identifier] = msg
                    return EventResult.DISCARD
                self.cache[identifier] = msg
                return EventResult.CHANGE
            else:
                self.cache.pop(identifier, None)
                return EventResult.DEL

    def __init__(self, observer) -> None:
        self.observer = observer

        # By default, the groups (aka. membership groups) is RTMGRP_DEFAULT,
        # which includes neighbours, traffic control, MPLS, rules, etc. We
        # don't want to receive notifications for those.
        groups = (
            pyroute2.netlink.rtnl.RTMGRP_LINK
            | pyroute2.netlink.rtnl.RTMGRP_IPV4_IFADDR
            | pyroute2.netlink.rtnl.RTMGRP_IPV6_IFADDR
            | pyroute2.netlink.rtnl.RTMGRP_IPV4_ROUTE
            | pyroute2.netlink.rtnl.RTMGRP_IPV6_ROUTE
        )

        self.ipr = pyroute2.IPRoute(groups=groups)

        # The caches allow us to discard repetitive NEW events or to emit
        # CHANGE events when appropriate.
        self.link_cache = LinkCache()
        self.addr_cache = AddrCache()
        self.route_cache = RouteCache()

        self.msg_handlers = {
            "RTM_NEWLINK": self.MsgHandler(
                new="RTM_NEWLINK",
                cache=self.link_cache,
                observer_callback=self.observer.link_change,
                build_event_data=EventData.build_link_event_data,
            ), "RTM_NEWADDR": self.MsgHandler(
                new="RTM_NEWADDR",
                cache=self.addr_cache,
                observer_callback=self.observer.addr_change,
                build_event_data=EventData.build_addr_event_data,
            ), "RTM_NEWROUTE": self.MsgHandler(
                new="RTM_NEWROUTE",
                cache=self.route_cache,
                observer_callback=self.observer.route_change,
                build_event_data=EventData.build_route_event_data,
            ),
        }
        self.msg_handlers["RTM_DELLINK"] = self.msg_handlers["RTM_NEWLINK"]
        self.msg_handlers["RTM_DELADDR"] = self.msg_handlers["RTM_NEWADDR"]
        self.msg_handlers["RTM_DELROUTE"] = self.msg_handlers["RTM_NEWROUTE"]

    def start(self) -> None:
        # By default IPRoute adds membership for RTMGRP_LINK
        self.ipr.bind()

        for msg in self.ipr.get_links():
            self.handle_nl_msg(msg)
        for msg in self.ipr.get_addr():
            self.handle_nl_msg(msg)
        for msg in self.ipr.get_routes():
            self.handle_nl_msg(msg)

    def fileno(self) -> int:
        return self.ipr.fileno()

    def handle_nl_msg(self, msg: nlmsg) -> None:
        handler = self.msg_handlers[msg["event"]]
        result = handler.cache_handle_nl_msg(msg)

        if result == EventResult.DISCARD:
            return

        handler.observer_callback(result.value, handler.build_event_data(msg))

    def data_ready(self) -> None:
        for msg in self.ipr.get():
            self.handle_nl_msg(msg)

    def set_link_flags(self, ifindex: int, flags: int) -> None:
        self.ipr.link("set", index=ifindex, flags=flags, mask=flags)

    def unset_link_flags(self, ifindex: int, flags: int) -> None:
        self.ipr.link('set', index=ifindex, flags=0x0, mask=flags)
