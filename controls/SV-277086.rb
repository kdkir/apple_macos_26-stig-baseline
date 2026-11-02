control 'SV-277086' do
  title 'The macOS system must disable Network File System (NFS) service.'
  desc 'Support for NFS services is nonessential and, therefore, must be disabled. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', %q(Verify the macOS system is configured to disable NFS service with the following commands:

isDisabled=$(/sbin/nfsd status | /usr/bin/awk '/nfsd service/ {print $NF}')    
  if [[ "$isDisabled" == "disabled" ]] && [[ -z $(/usr/bin/pgrep nfsd) ]]; then
    echo "pass"
  else
    echo "fail"
  fi

If the result is not "pass", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable NFS service with the following commands:

/bin/launchctl disable system/com.apple.nfsd
/bin/rm -rf /etc/exports

The system may need a restart for the update to take effect.'
  impact 0.5
  tag check_id: 'C-81241r1148708_chk'
  tag severity: 'medium'
  tag gid: 'V-277086'
  tag rid: 'SV-277086r1268226_rule'
  tag stig_id: 'APPL-26-002003'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81146r1148709_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
