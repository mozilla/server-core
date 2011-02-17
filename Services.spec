%define name python26-services
%define pythonname Services
%define version 0.2
%define unmangled_version 0.2
%define unmangled_version 0.2
%define release 10 

Summary: Services core tools
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
Requires: nginx memcached gunicorn openldap-devel mysql-devel python26 python26-memcached python26-setuptools python26-webob python26-paste python26-pastedeploy python26-sqlalchemy python26-simplejson python26-routes python26-ldap python26-mysql-python
Obsoletes: python26-synccore

Url: https://hg.mozilla.org/services/server-core

%description
========
Services
========

Core library that provides these features:

- CEF logger
- Config reader/writer
- Plugin system
- Base WSGI application for Services servers
- Error codes for Sync
- Authentication back ends for Services
- Captcha wrappers


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
