%define name python26-syncstorage
%define pythonname SyncStorage
%define version 0.1
%define unmangled_version 0.1
%define unmangled_version 0.1
%define release 1

Summary: Sync Storage server
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{pythonname}-%{unmangled_version}.tar.gz
License: MPL
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{pythonname}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Tarek Ziade <tarek@mozilla.com>
Requires: nginx memcached gunicorn python26 pylibmc python26-setuptools python26-webob python26-paste python26-pastedeploy python26-synccore python26-sqlalchemy python26-simplejson python26-routes

Url: https://hg.mozilla.org/services/server-core

%description
=========
Sync Core
=========

Core library that provides these features:

- CEF logger
- Config reader/writer
- Plugin system
- Base WSGI application for Sync servers
- Error codes for Sync
- Authentication back ends for Sync


%prep
%setup -n %{pythonname}-%{unmangled_version} -n %{pythonname}-%{unmangled_version}

%build
python2.6 setup.py build

%install
python2.6 setup.py install --single-version-externally-managed --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES

%defattr(-,root,root)
