control 'SV-277051' do
  title 'The macOS system must disable root login.'
  desc 'To ensure individual accountability and prevent unauthorized access, logging in as root at the login window must be disabled.

The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator, and administrator users must never log in directly as root.

'
  desc 'check', 'Verify the macOS system is configured to disable root login with the following command:

/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c "/usr/bin/false"

If the result is not "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable root login with the following command:

/usr/bin/dscl . -create /Users/root UserShell /usr/bin/false'
  impact 0.5
  tag check_id: 'C-81206r1148603_chk'
  tag severity: 'medium'
  tag gid: 'V-277051'
  tag rid: 'SV-277051r1148605_rule'
  tag stig_id: 'APPL-26-000100'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-81111r1148604_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000109-GPOS-00056', 'SRG-OS-000364-GPOS-00151']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-004045', 'CCI-001813']
  tag nist: ['IA-2', 'IA-2 (5)', 'CM-5 (1) (a)']

  describe command('/usr/bin/dscl . -read /Users/root UserShell') do
    its('stdout') { should match(%r{/usr/bin/false}) }
  end
end
