control 'SV-277160' do
  title 'The macOS system must require users to reauthenticate for privilege escalation when using the "sudo" command.'
  desc 'The file /etc/sudoers must include a timestamp_timout of 0.

Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability or change user authenticators, it is critical that the user reauthenticate.

'
  desc 'check', 'Verify the macOS system requires reauthentication when using the "sudo" command to elevate privileges with the following command:

/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Authentication timestamp timeout: 0.0 minutes"

If the result is not "1", this is a finding.'
  desc 'fix', %q(Configure the macOS system to require reauthentication when using "sudo" with the following command:

/usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/timestamp_timeout/d' '{}' \;
/bin/echo "Defaults timestamp_timeout=0" >> /etc/sudoers.d/mscp)
  impact 0.5
  tag check_id: 'C-81315r1148930_chk'
  tag severity: 'medium'
  tag gid: 'V-277160'
  tag rid: 'SV-277160r1148932_rule'
  tag stig_id: 'APPL-26-004022'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-81220r1148931_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
