control 'SV-277114' do
  title 'The macOS system must disable Screen Sharing and Apple Remote Desktop.'
  desc 'Support for both Screen Sharing and Apple Remote Desktop is nonessential and must be disabled.

The information system must be configured to provide only essential capabilities. Disabling Screen Sharing and Apple Remote Desktop helps prevent unauthorized connection of devices, transfer of information, and tunneling.'
  desc 'check', %q(Verify the macOS system is configured to disable Screen Sharing and Apple Remote Desktop with the following command:

result="FAIL"
  enabled=$(/bin/launchctl print-disabled system | /usr/bin/grep '"com.apple.screensharing" => enabled')
  running=$(/bin/launchctl print system/com.apple.screensharing 2>/dev/null)
  
  if [[ -z "$running" ]] && [[ -z "$enabled" ]]; then
    result="PASS"
  elif [[ -n "$running" ]]; then
    result=result+" RUNNING"
  elif [[ -n "$enabled" ]]; then
    result=result+" ENABLED"
  fi
  echo $result

If the result is not "PASS", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Screen Sharing and Apple Remote Desktop with the following command:

/bin/launchctl bootout system/com.apple.screensharing
/bin/launchctl disable system/com.apple.screensharing

Note: This will apply to the whole system.'
  impact 0.5
  tag check_id: 'C-81269r1149327_chk'
  tag severity: 'medium'
  tag gid: 'V-277114'
  tag rid: 'SV-277114r1268226_rule'
  tag stig_id: 'APPL-26-002050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81174r1149328_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
