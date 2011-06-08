Name: libxsp-xio-driver
Version: 1.0
Release: 1
Summary: XSP XIO RPM

Group: Application/Network
License: GPL
URL: http://damsl.cis.udel.edu/projects/xsp
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
Requires: libxsp-client
Prefix: %{_libdir}

Packager: Ezra Kissel <kissel@cis.udel.edu>
Vendor: Distributed and Metasystems Lab (DAMSL), University of Delaware
Provides: xio-xsp

%define __os_install_post /usr/lib/rpm/brp-compress

%description
The Globus XIO-XSP Driver.

%files
%defattr(775,root,root)
%{_libdir}/libglobus_xio_xsp*

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
#%configure --with-xsp-path=/usr/local --with-flavor=gcc32dbg
make

%install
#make AM_INSTALL_PROGRAM_FLAGS="" DESTDIR=${RPM_BUILD_ROOT} install
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT