Name:           check-snmp-extras
Version:        0.0.1
Release:        1%{?dist}
Summary:        Extra SNMP check plugins

License: GPL
URL: https://github.com/Isma399/check_4_icinga            
Source: %{name}-%{version}.tar.gz

%description
Extra SNMP check plugins, written in C.

%prep

%setup -q

mkdir build

%build
pushd build
%cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} -DCMAKE_BUILD_TYPE=Release ../
popd

%install
pushd build
%make_install
popd

%files
%defattr(0644, root, root, 0755)

%attr(0755, -, -) %{_libdir}/nagios/plugins/check_snmp_disk
%attr(0755, -, -) %{_libdir}/nagios/plugins/check_snmp_load

%config %{_datadir}/icinga2/include/plugins-contrib.d/check_snmp_extras.conf
