"""Tests for port_list.py."""

from __future__ import annotations

import pytest

from port_scanner.port_list import expand_ports, list_presets


class TestExpandPorts:
    def test_single_port(self):
        assert expand_ports("22") == [22]

    def test_comma_separated(self):
        assert expand_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert expand_ports("1000-1002") == [1000, 1001, 1002]

    def test_mixed(self):
        assert expand_ports("22,80,1000-1002,443") == [22, 80, 443, 1000, 1001, 1002]

    def test_dedup(self):
        assert expand_ports("22,22,80") == [22, 80]

    def test_range_inclusive_end(self):
        assert expand_ports("1-3") == [1, 2, 3]

    def test_ensure_all_65535(self):
        # 'all' preset covers 1..65535
        assert expand_ports("all") == list(range(1, 65536))

    def test_preset_top100_length(self):
        # top100 should have exactly 100 entries
        ports = expand_ports("top100")
        assert len(ports) == 100
        assert ports == sorted(set(ports))

    def test_preset_web(self):
        assert expand_ports("web") == [80, 443, 8080, 8443, 8888, 9443, 10443]

    def test_preset_common_length(self):
        # common should have a reasonable number; just check it's non-empty
        common = expand_ports("common")
        assert isinstance(common, list)
        assert len(common) > 0
        assert common == sorted(set(common))

    def test_invalid_non_numeric(self):
        with pytest.raises(ValueError, match="Invalid port entry"):
            expand_ports("abc")

    def test_invalid_out_of_range_high(self):
        with pytest.raises(ValueError, match="out of range"):
            expand_ports("99999")

    def test_invalid_out_of_range_low(self):
        with pytest.raises(ValueError, match="out of range"):
            expand_ports("0")

    def test_invalid_inverted_range(self):
        with pytest.raises(ValueError, match="Inverted range"):
            expand_ports("80-22")

    def test_empty_spec(self):
        with pytest.raises(ValueError, match="empty"):
            expand_ports("")

    def test_invalid_spec_with_extra_junk(self):
        with pytest.raises(ValueError):
            expand_ports("22,xyz")

    def test_whitespace_handling(self):
        assert expand_ports(" 22 , 80 , 443 ") == [22, 80, 443]

    def test_range_single_port_equality(self):
        # '22-22' should be same as '22'
        assert expand_ports("22-22") == [22]

    def test_large_range_validity(self):
        # 1-1024 must be valid
        ports = expand_ports("1-1024")
        assert len(ports) == 1024
        assert ports[0] == 1
        assert ports[-1] == 1024

    def test_known_presets_are_sorted(self):
        for name in list_presets():
            ports = expand_ports(name)
            assert ports == sorted(set(ports)), f"Preset '{name}' not sorted/deduped"


class TestListPresets:
    def test_presets_include_common(self):
        assert "top100" in list_presets()
        assert "web" in list_presets()
        assert "common" in list_presets()
        assert "all" in list_presets()

    def test_presets_sorted(self):
        presets = list_presets()
        assert presets == sorted(presets)
