Name: libxsp-xio-driver
Version: 1.0
Release: 8
Summary: XSP Globus XIO RPM

Group: Application/Network
License: GPL
URL: http://damsl.cs.indiana.edu/projects/xsp
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
Requires: libxsp-client

Packager: Ezra Kissel <ezkissel@indiana.edu>
Vendor: Distributed and Metasystems Lab (DAMSL), Indiana University
Provides: xio-xsp

%define __os_install_post /usr/lib/rpm/brp-compress

%description
The Globus XIO-XSP Driver.

%prep
rm -rf $RPM_BUILD_ROOT
%setup -q

%build
#./configure \
#--prefix=%{_prefix} \
#--exec-prefix=%{_exec_prefix} \
#--libexecdir=%{_exec_prefix} \
#--sysconfdir=%{_sysconfdir} \
#--datadir=%{_datadir} \
#make %{?_smp_mflags}
%configure --sbindir=/usr/sbin --with-xsp-path=/usr/local --with-flavor=gcc64
make

%install
make prefix=$RPM_BUILD_ROOT/usr exec_prefix=$RPM_BUILD_ROOT/usr bindir=$RPM_BUILD_ROOT/usr/bin sysconfdir=$RPM_BUILD_ROOT/etc datadir=$RPM_BUILD_ROOT/usr/share includedir=$RPM_BUILD_ROOT/usr/include libdir=$RPM_BUILD_ROOT/%{_libdir} libexecdir=$RPM_BUILD_ROOT/usr/libexec localstatedir=$RPM_BUILD_ROOT/var sharedstatedir=$RPM_BUILD_ROOT/usr/com mandir=$RPM_BUILD_ROOT/usr/share/man infodir=$RPM_BUILD_ROOT/usr/share/info install
mv $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver_gcc64.a $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver.a
mv $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver_gcc64.la $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver.la
mv $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver_gcc64.so.%{version}.%{release} $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver.so.%{version}.%{release}
cd $RPM_BUILD_ROOT/%{_libdir} && ln -sf libglobus_xio_xsp_driver.so.%{version}.%{release} libglobus_xio_xsp_driver.so.1
cd $RPM_BUILD_ROOT/%{_libdir} && ln -sf libglobus_xio_xsp_driver.so.1 libglobus_xio_xsp_driver.so
rm $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver_gcc64.so.1
rm $RPM_BUILD_ROOT/%{_libdir}/libglobus_xio_xsp_driver_gcc64.so

%files
%defattr(775,root,root)
%{_libdir}/libglobus_xio_xsp_driver.*

%post

%clean
rm -rf $RPM_BUILD_ROOT
