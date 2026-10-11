# HyprNova RPM spec. Build: packaging/build-rpm.sh  (needs rpm-build)
# Validated only by rpmbuild -bl lint so far; an actual dnf/yum install is
# NOT RUN (needs a disposable VM) -- see packaging/README.md.
Name:           hyprnova
Version:        1.0.0
Release:        1%{?dist}
Summary:        HyprNova Anti-Malware Sec -- endpoint agent, CLI and console
License:        Apache-2.0
URL:            https://hyprnova.local
Source0:        hyprnova-%{version}.tar.gz

%description
Behavioural EDR for Linux: ransomware containment with evidence preservation,
memory forensics, yara-lite + KVRT + ClamAV scanning, package-integrity and
sshd weak-settings audits, CrowdSec integration, shadow-copy recovery,
AI analyst (advises-only).

%install
mkdir -p %{buildroot}%{_bindir} %{buildroot}%{_unitdir} \
         %{buildroot}%{_sharedstatedir}/hyprnova/quarantine \
         %{buildroot}%{_sharedstatedir}/hyprnova/memory \
         %{buildroot}%{_sysconfdir}/hyprnova/rules \
         %{buildroot}%{_datadir}/hyprnova
install -m755 build/hyprnovad    %{buildroot}%{_bindir}/
install -m755 build/hyprnova-cli %{buildroot}%{_bindir}/
install -m644 packaging/hyprnovad.service %{buildroot}%{_unitdir}/
install -m755 scripts/install-deps.sh %{buildroot}%{_datadir}/hyprnova/
build/hyprnovad --dump-config > %{buildroot}%{_sysconfdir}/hyprnova/agent.json
chmod 600 %{buildroot}%{_sysconfdir}/hyprnova/agent.json

%files
%license LICENSE
%{_bindir}/hyprnovad
%{_bindir}/hyprnova-cli
%{_unitdir}/hyprnovad.service
%{_datadir}/hyprnova/
%dir %attr(700,root,root) %{_sharedstatedir}/hyprnova
%dir %attr(700,root,root) %{_sharedstatedir}/hyprnova/quarantine
%dir %attr(700,root,root) %{_sharedstatedir}/hyprnova/memory
%dir %attr(755,root,root) %{_sysconfdir}/hyprnova
%dir %attr(755,root,root) %{_sysconfdir}/hyprnova/rules
%config(noreplace) %attr(600,root,root) %{_sysconfdir}/hyprnova/agent.json

%post
%systemd_post hyprnovad.service

%preun
%systemd_preun hyprnovad.service

%postun
%systemd_postun_with_restart hyprnovad.service

%changelog
* Sat Oct 10 2026 HyprNova <dev@hyprnova.local> - 1.0.0-1
- Initial packaged release (agent, CLI, systemd unit; config noreplace;
  quarantine+state preserved across upgrades, archived on erase).
