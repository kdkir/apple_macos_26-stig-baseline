control 'SV-277032' do
  title 'The macOS system must disable hot corners.'
  desc 'Hot corners must be disabled.

The information system conceals, via the session lock, information previously visible on the display with a publicly viewable image. Although hot corners can be used to initiate a session lock or to launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.'
  desc 'check', %q(Verify the macOS system is configured to disable hot corners with the following command:

/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '"wvous-bl-corner" = 0|"wvous-br-corner" = 0|"wvous-tl-corner" = 0|"wvous-tr-corner" = 0'

If the result is not "4", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable hot corners by installing the "com.apple.ManagedClient.preferences" configuration profile.'
  impact 0.5
  tag check_id: 'C-81187r1148546_chk'
  tag severity: 'medium'
  tag gid: 'V-277032'
  tag rid: 'SV-277032r1148548_rule'
  tag stig_id: 'APPL-26-000007'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-81092r1148547_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
