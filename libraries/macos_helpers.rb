# frozen_string_literal: true

require 'shellwords'
require 'time'

# Runs a script under /bin/zsh (the shell DISA check procedures are written for), so that
# pipelines and substitutions execute entirely in one privileged shell when using --sudo.
class MacosZsh < Inspec.resource(1)
  name 'macos_zsh'
  supports platform: 'darwin'
  desc 'Runs a script with /bin/zsh and exposes stdout/stderr/exit_status.'
  example <<~EXAMPLE
    describe macos_zsh('/usr/bin/sudo -V | /usr/bin/grep -c "Log when a command is allowed"') do
      its('stdout') { should cmp 1 }
    end
  EXAMPLE

  def initialize(script)
    @script = script
  end

  def result
    @result ||= inspec.command("/bin/zsh -c #{Shellwords.escape(@script)}")
  end

  def stdout
    result.stdout.strip
  end

  def stderr
    result.stderr.strip
  end

  def exit_status
    result.exit_status
  end

  def lines
    stdout.lines.map(&:strip).reject(&:empty?)
  end

  def to_s
    "zsh script `#{@script.lines.first.to_s.strip}`"
  end
end

# Local user accounts and file metadata gathered in a single round trip.
class MacosLocalUsers < Inspec.resource(1)
  name 'macos_local_users'
  supports platform: 'darwin'
  desc 'Local directory service users from dscl.'
  example <<~EXAMPLE
    macos_local_users.interactive.each { |u| ... }
  EXAMPLE

  # Users with UniqueID greater than 500 (the population the STIG SSH client checks iterate).
  def standard
    @standard ||= inspec.command('/usr/bin/dscl . -list /Users UniqueID').stdout.lines.filter_map do |line|
      name, uid = line.split
      name if uid.to_i > 500
    end
  end

  # Users with a login shell, excluding system (_) accounts, root, and /usr/bin/false shells.
  def interactive
    @interactive ||= inspec.command('/usr/bin/dscl . -list /Users UserShell').stdout.lines.filter_map do |line|
      name, shell = line.split(/\s+/, 2)
      next if name.nil? || name.start_with?('_') || name == 'root' || shell.to_s.include?('/usr/bin/false')

      name
    end
  end

  def to_s
    'macOS local users'
  end
end

# File owner/group/mode for many paths in one stat call; missing paths are omitted.
class MacosFileStats < Inspec.resource(1)
  name 'macos_file_stats'
  supports platform: 'darwin'
  desc 'Owner, group and octal mode for a list of files (BSD stat).'
  example <<~EXAMPLE
    macos_file_stats(['/var/log/system.log']).entries
  EXAMPLE

  Entry = Struct.new(:path, :owner, :group, :mode) do
    def more_permissive_than?(max_mode)
      (mode & ~max_mode & 0o7777) != 0
    end
  end

  STAT_FORMAT = "'%Su:%Sg:%Lp:%N'"

  # Either a list of paths, or { dir:, type: } for every entry directly inside dir
  # (optionally only files of type). InSpec passes resource arguments positionally.
  def initialize(paths_or_opts = nil)
    if paths_or_opts.is_a?(Hash)
      @paths = []
      @dir = paths_or_opts[:dir]
      @type = paths_or_opts[:type]
    else
      @paths = Array(paths_or_opts).compact.uniq
    end
  end

  def entries
    @entries ||= inspec.command(stat_command).stdout.lines.filter_map do |line|
      owner, group, mode, path = line.strip.split(':', 4)
      Entry.new(path, owner, group, mode.to_i(8)) if path
    end
  end

  def to_s
    @dir ? "macOS file stats in #{@dir}" : 'macOS file stats'
  end

  private

  def stat_command
    if @dir
      type_filter = @type ? " -type #{@type}" : ''
      "/usr/bin/find #{Shellwords.escape(@dir)} -mindepth 1 -maxdepth 1#{type_filter} -exec /usr/bin/stat -f #{STAT_FORMAT} {} +"
    elsif @paths.empty?
      '/usr/bin/true'
    else
      "/usr/bin/stat -f #{STAT_FORMAT} #{@paths.map { |p| Shellwords.escape(p) }.join(' ')} 2>/dev/null"
    end
  end
end

# A right from the authorization database (`security authorizationdb read`).
class MacosAuthorizationdb < Inspec.resource(1)
  name 'macos_authorizationdb'
  supports platform: 'darwin'
  desc 'Parsed definition of an authorization right.'
  example <<~EXAMPLE
    describe macos_authorizationdb('system.preferences') do
      its(['group']) { should cmp 'admin' }
    end
  EXAMPLE

  def initialize(right)
    @right = right
  end

  def params
    @params ||= MacosPlist.parse(inspec.command("/usr/bin/security -q authorizationdb read #{Shellwords.escape(@right)}").stdout) || {}
  end

  def [](key)
    params[key]
  end

  # The right's "rule" array (rules it delegates to).
  def rules
    Array(params['rule'])
  end

  def to_s
    "authorizationdb right #{@right}"
  end
end

# Installed configuration profiles (`profiles show -output stdout-xml`).
class MacosConfigurationProfiles < Inspec.resource(1)
  name 'macos_configuration_profiles'
  supports platform: 'darwin'
  desc 'Values found in installed configuration profile payloads.'
  example <<~EXAMPLE
    describe macos_configuration_profiles do
      its('disabled_system_settings') { should include 'com.apple.BluetoothSettings' }
    end
  EXAMPLE

  def params
    @params ||= MacosPlist.parse(inspec.command('/usr/bin/profiles show -output stdout-xml').stdout) || {}
  end

  # Every value of +key+ in any installed payload.
  def values(key)
    MacosPlist.find_values(params, key)
  end

  def disabled_system_settings
    values('DisabledSystemSettings').flatten
  end

  def to_s
    'macOS configuration profiles'
  end
end
