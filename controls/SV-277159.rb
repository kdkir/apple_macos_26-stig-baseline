control 'SV-277159' do
  title 'The macOS system must configure Apple System Log (ASL) files to mode 640 or less permissive.'
  desc 'The ASLs must be configured to be writable by root and readable only by the root user and group wheel. To achieve this, ASL files must be configured to mode 640 permissive or less, thereby preventing normal users from reading, modifying, or deleting audit logs.

System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.

'
  desc 'check', %q(Verify the macOS system is configured with ASL files to mode 640 or less permissive with the following command:

/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the result is not "0", this is a finding.)
  desc 'fix', %q(Configure the macOS system with ASL files to mode 640 with the following command:

/bin/chmod 640 $(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk -F":" '!/640/{print $2}'))
  impact 0.5
  tag check_id: 'C-81314r1148927_chk'
  tag severity: 'medium'
  tag gid: 'V-277159'
  tag rid: 'SV-277159r1148929_rule'
  tag stig_id: 'APPL-26-004002'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-81219r1148928_fix'
  tag satisfies: ['SRG-OS-000205-GPOS-00083', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']

  asl_configs = ['/etc/asl.conf'] + command('/bin/ls /etc/asl').stdout.split.map { |f| "/etc/asl/#{f}" }
  asl_files = asl_configs.flat_map { |f| file(f).content.to_s.lines.grep(/\A>/).filter_map { |l| l.split[1] } }
  asl_files = asl_files.map { |p| p.start_with?('/') ? p : "/var/log/#{p}" }
  offenders = macos_file_stats(asl_files).entries.select { |e| e.more_permissive_than?(0o640) }.map(&:path)

  describe 'ASL log files more permissive than 0640' do
    subject { offenders }
    it { should be_empty }
  end
end
