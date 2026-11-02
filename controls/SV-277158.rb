control 'SV-277158' do
  title 'The macOS system must configure Apple System Log (ASL) files owned by root and group to wheel.'
  desc 'The ASL must be owned by root.

ASLs contain sensitive data about the system and users. Setting ASL files to be readable and writable only by system administrators mitigates the risk.

'
  desc 'check', %q(Verify the macOS system is configured with ASL files owned by root and group to wheel with the following command:

/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the result is not "0", this is a finding.)
  desc 'fix', %q(Configure the macOS system with ASL files owned by root and group to wheel with the following command:

/usr/sbin/chown root:wheel $(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/awk -F":" '!/^root:wheel:/{print $3}'))
  impact 0.5
  tag check_id: 'C-81313r1148924_chk'
  tag severity: 'medium'
  tag gid: 'V-277158'
  tag rid: 'SV-277158r1148926_rule'
  tag stig_id: 'APPL-26-004001'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-81218r1148925_fix'
  tag satisfies: ['SRG-OS-000205-GPOS-00083', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']

  asl_configs = ['/etc/asl.conf'] + command('/bin/ls /etc/asl').stdout.split.map { |f| "/etc/asl/#{f}" }
  asl_files = asl_configs.flat_map { |f| file(f).content.to_s.lines.grep(/\A>/).filter_map { |l| l.split[1] } }
  asl_files = asl_files.map { |p| p.start_with?('/') ? p : "/var/log/#{p}" }
  offenders = macos_file_stats(asl_files).entries.reject { |e| e.owner == 'root' && e.group == 'wheel' }.map(&:path)

  describe 'ASL log files not owned by root:wheel' do
    subject { offenders }
    it { should be_empty }
  end
end
