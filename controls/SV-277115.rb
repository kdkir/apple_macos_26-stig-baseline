control 'SV-277115' do
  title 'The macOS system must disable the System Settings pane for Wallet and Apple Pay.'
  desc 'The System Settings pane for Wallet and Apple Pay must be disabled.

Disabling the System Settings pane prevents users from configuring Wallet and Apple Pay. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', %q(Verify the macOS system is configured to disable the System Settings pane for Wallet and Apple Pay with the following command:

/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c "com.apple.WalletSettingsExtension"

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the System Settings pane for Wallet and Apple Pay by installing the "com.apple.systempreferences" configuration profile.'
  impact 0.5
  tag check_id: 'C-81270r1148795_chk'
  tag severity: 'medium'
  tag gid: 'V-277115'
  tag rid: 'SV-277115r1148797_rule'
  tag stig_id: 'APPL-26-002052'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81175r1148796_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
