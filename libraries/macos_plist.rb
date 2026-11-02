# frozen_string_literal: true

require 'rexml/document'

# Minimal XML property list parser used by the macOS resources in this profile.
# Converts a plist document (or a string containing one, e.g. pwpolicy output with a
# leading banner line) into native Ruby objects.
module MacosPlist
  module_function

  def parse(text)
    return nil if text.nil?

    start = text.index('<?xml') || text.index('<plist')
    return nil if start.nil?

    doc = REXML::Document.new(text[start..])
    plist = doc.root
    return nil if plist.nil?

    node = plist.name == 'plist' ? plist.elements[1] : plist
    node.nil? ? nil : convert(node)
  rescue REXML::ParseException
    nil
  end

  def convert(node)
    case node.name
    when 'dict'
      convert_dict(node)
    when 'array'
      node.elements.map { |child| convert(child) }
    when 'integer'
      node.text.to_i
    when 'real'
      node.text.to_f
    when 'true'
      true
    when 'false'
      false
    else
      node.text.to_s
    end
  end

  def convert_dict(node)
    result = {}
    key = nil
    node.elements.each do |child|
      if child.name == 'key'
        key = child.text.to_s
      else
        result[key] = convert(child)
        key = nil
      end
    end
    result
  end

  # Recursively collects every value stored under +key+ anywhere in +obj+.
  def find_values(obj, key)
    case obj
    when Hash
      obj.flat_map { |k, v| (k == key ? [v] : []) + find_values(v, key) }
    when Array
      obj.flat_map { |v| find_values(v, key) }
    else
      []
    end
  end
end
