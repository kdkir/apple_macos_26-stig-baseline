control 'SV-277127' do
  title 'The macOS system must disable Bluetooth Sharing.'
  desc 'Bluetooth Sharing must be disabled.

Bluetooth Sharing allows users to wirelessly transmit files between the macOS and Bluetooth-enabled devices, including personally owned cellphones and tablets. A malicious user might introduce viruses or malware onto the system or extract sensitive files via Bluetooth Sharing. When Bluetooth Sharing is disabled, this risk is mitigated.

[NOTE]
  ====
  The check and fix are for the last logged in user. To get the last logged in user, run the following.
  [source,bash]
  ----
  CURRENT_USER=$( /usr/bin/defaults read /Library/Preferences/com.apple.loginwindow lastUserName )
  ----
  ====

'
  desc 'check', %q(Verify the macOS system is configured to disable Bluetooth sharing with the following commands:

CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled

If the result is not "0", this is a finding.)
  desc 'fix', %q(Configure the macOS system to disable Bluetooth sharing with the following commands:

CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false)
  impact 0.5
  tag check_id: 'C-81282r1148831_chk'
  tag severity: 'medium'
  tag gid: 'V-277127'
  tag rid: 'SV-277127r1268226_rule'
  tag stig_id: 'APPL-26-002110'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81187r1148832_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000381']
  tag nist: ['AC-3', 'CM-7 a']
end
