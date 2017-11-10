Name:           globus-gridftp-server-ceph
Version:        1.3
Release:        1%{?dist}
Summary:        Globus GridFTP Server - Ceph Plugin

Group:          System Environment/Libraries
License:        STFC
URL:            https://github.com/stfc/gridFTPCephPlugin
Source0:        gridFTPCephPlugin.tar.gz

Packager:       Ian Johnson
Vendor:         STFC Scientific Computing Department

Requires:       globus-gridftp-server-progs
# We need /usr/bin/xrdacctest from xrootd-server for parsing /etc/grid-security/authdb
Requires:       xrootd-server
Requires:       xrootd-libs
Requires:       libradosstriper1

BuildRequires:  globus-gridftp-server-devel
BuildRequires:  xrootd-devel
BuildRequires:  librados2-devel
BuildRequires:  libradosstriper1-devel
BuildRequires:  cmake

BuildArch:      x86_64
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)


%description
A plugin for Globus GridFTP to use a Ceph object store as a backend.


%prep
%setup -n gridFTPCephPlugin


%build
cmake ./
make


%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

install -m 755 -d $RPM_BUILD_ROOT%{_libdir}
install libglobus_gridftp_server_ceph.so $RPM_BUILD_ROOT%{_libdir}


%clean
[ "x${RPM_BUILD_ROOT}" != "x/" ] && rm -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(0755,root,root,-)
%{_libdir}/libglobus_gridftp_server_ceph.so


%changelog
* Fri Nov 10 2017 Ian Johnson <ian.johnson@stfc.ac.uk> 1.3
- Update library names in BuildRequires

* Mon Feb 06 2017 Bob Builder <bob@buildfarm.com> 1.1
- Add more xrootd requirements.

* Mon Feb 06 2017 Bob Builder <bob@buildfarm.com> 0.9
- First draft of GridFTP plugin spec file.
