# frozen_string_literal: true

require 'json'
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'mysql'))
Puppet::Type.type(:mysql_user).provide(:mysql, parent: Puppet::Provider::Mysql) do
  desc 'manage users for a mysql database.'
  commands mysql_raw: 'mysql'

  # Build a property_hash containing all the discovered information about MySQL
  # users.
  def self.instances
    users = mysql_caller("SELECT CONCAT(User, '@',Host) AS User FROM mysql.user where HOST IS NOT NULL AND HOST != ''", 'regular').split("\n")
    # users = users_full.reject { |user| user == 'PUBLIC@' }
    # To reduce the number of calls to MySQL we collect all the properties in
    # one big swoop.
    users.map do |name|
      # rubocop:disable Layout/LineLength
      if !mysqld_version.nil? && newer_than('mysql' => '5.7.6', 'percona' => '5.7.6')
        query = "SELECT MAX_USER_CONNECTIONS, MAX_CONNECTIONS, MAX_QUESTIONS, MAX_UPDATES, SSL_TYPE, SSL_CIPHER, X509_ISSUER, X509_SUBJECT, AUTHENTICATION_STRING, PLUGIN FROM mysql.user WHERE CONCAT(user, '@', host) = '#{name}'"
      elsif !mysqld_version.nil? && newer_than('mariadb' => '10.4')
        query = "SELECT CAST(IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.max_user_connections'), 0) AS SIGNED)       MAX_USER_CONNECTIONS,
                 CAST(IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.max_connections'), 0) AS UNSIGNED)                 MAX_CONNECTIONS,
                 CAST(IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.max_questions'), 0) AS UNSIGNED)                   MAX_QUESTIONS,
                 CAST(IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.max_updates'), 0) AS UNSIGNED)                     MAX_UPDATES,
                 ELT(IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.ssl_type'), 0) + 1, '', 'ANY', 'X509', 'SPECIFIED') SSL_TYPE,
                 IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.ssl_cipher'), '')                                       SSL_CIPHER,
                 IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.x509_issuer'), '')                                      X509_ISSUER,
                 IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.x509_subject'), '')                                     X509_SUBJECT,
                 IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.authentication_string'), '')                            PASSWORD,
                 IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.plugin'), '')                                           PLUGIN,
                 IFNULL(JSON_VALUE(`mysql`.`global_priv`.`Priv`, '$.authentication_string'), '')                            AUTHENTICATION_STRING,
                 IFNULL(JSON_QUERY(priv, '$.auth_or'), '')                                                                  ADDITIONAL_PLUGINS
                 FROM `mysql`.`global_priv` WHERE CONCAT(user, '@', host) = '#{name}'"
      elsif !mysqld_version.nil? && newer_than('mariadb' => '10.1.21')
        query = "SELECT MAX_USER_CONNECTIONS, MAX_CONNECTIONS, MAX_QUESTIONS, MAX_UPDATES, SSL_TYPE, SSL_CIPHER, X509_ISSUER, X509_SUBJECT, PASSWORD, PLUGIN, AUTHENTICATION_STRING FROM mysql.user WHERE CONCAT(user, '@', host) = '#{name}'"
      else
        query = "SELECT MAX_USER_CONNECTIONS, MAX_CONNECTIONS, MAX_QUESTIONS, MAX_UPDATES, SSL_TYPE, SSL_CIPHER, X509_ISSUER, X509_SUBJECT, PASSWORD /*!50508 , PLUGIN */ FROM mysql.user WHERE CONCAT(user, '@', host) = '#{name}'"
      end
      # rubocop:enable Layout/LineLength
      @max_user_connections, @max_connections_per_hour, @max_queries_per_hour, @max_updates_per_hour, ssl_type, ssl_cipher,
        x509_issuer, x509_subject, @password, @plugin, @authentication_string, additional_plugins = mysql_caller(query, 'regular').chomp.split(%r{\t})
      if !additional_plugins.nil? # can only be true for mariadb
        @socket_authentication = :false
        # MariaDB likes to swap unix_socket and other plugins. If any is unix_socket, set @socket_authentication to :true and use first non-unix-socket plugin for @plugin value with corresponding hash
        first_non_socket_plugin = nil
        all_plugins = [{ 'plugin' => @plugin, 'authentication_string' => @authentication_string }] + JSON.parse(additional_plugins)
        all_plugins.each do |plugin_hash|
          if plugin_hash['plugin'] == 'unix_socket'
            @socket_authentication = :true
          elsif !plugin_hash['plugin'].nil? && first_non_socket_plugin.nil?
            first_non_socket_plugin = plugin_hash
          end
        end
        if @plugin == 'unix_socket' && !first_non_socket_plugin.nil?
          @plugin = first_non_socket_plugin['plugin']
          @password = @authentication_string = first_non_socket_plugin['authentication_string']
        end
      else
        @socket_authentication = @plugin == socket_auth_plugin ? :true : :false
      end
      @tls_options = parse_tls_options(ssl_type, ssl_cipher, x509_issuer, x509_subject)
      if (newer_than('mariadb' => '10.1.21') && (@plugin == 'ed25519' || @plugin == 'mysql_native_password')) ||
         (newer_than('mariadb' => '11.6') && (@plugin == 'parsec')) ||
         (newer_than('mariadb' => '10.2.16') && older_than('mariadb' => '10.2.19')) ||
         (newer_than('mariadb' => '10.3.8') && older_than('mariadb' => '10.3.11'))
        # Some auth plugins (e.g. ed25519) use authentication_string
        # to store password hash or auth information
        # Old mariadb 10.2 or 10.3 store password hash in authentication_string
        # https://jira.mariadb.org/browse/MDEV-16238 https://jira.mariadb.org/browse/MDEV-16774
        @password = @authentication_string
      end
      new(name: name,
          ensure: :present,
          password_hash: @password,
          plugin: @plugin,
          max_user_connections: @max_user_connections,
          max_connections_per_hour: @max_connections_per_hour,
          max_queries_per_hour: @max_queries_per_hour,
          max_updates_per_hour: @max_updates_per_hour,
          tls_options: @tls_options,
          socket_authentication: @socket_authentication)
    end
  end

  def self.socket_auth_plugin
    return 'unix_socket' if mysqld_type == 'mariadb'
    'auth_socket'
  end

  def socket_auth_plugin
    self.class.socket_auth_plugin
  end

  # We iterate over each mysql_user entry in the catalog and compare it against
  # the contents of the property_hash generated by self.instances
  def self.prefetch(resources)
    users = instances
    # rubocop:disable Lint/AssignmentInCondition
    resources.each_key do |name|
      if provider = users.find { |user| user.name == name }
        resources[name].provider = provider
      end
    end
    # rubocop:enable Lint/AssignmentInCondition
  end

  def create
    # (MODULES-3539) Allow @ in username
    merged_name = @resource[:name].reverse.sub('@', "'@'").reverse
    password_hash = @resource.value(:password_hash)
    plugin = @resource.value(:plugin)
    max_user_connections = @resource.value(:max_user_connections) || 0
    max_connections_per_hour = @resource.value(:max_connections_per_hour) || 0
    max_queries_per_hour = @resource.value(:max_queries_per_hour) || 0
    max_updates_per_hour = @resource.value(:max_updates_per_hour) || 0
    tls_options = @resource.value(:tls_options) || ['NONE']
    socket_authentication = @resource.value(:socket_authentication) || :false

    password_hash = password_hash.unwrap if password_hash.is_a?(Puppet::Pops::Types::PSensitiveType::Sensitive)

    # Use CREATE USER to be compatible with NO_AUTO_CREATE_USER sql_mode
    # This is also required if you want to specify a authentication plugin
    self.class.mysql_caller("CREATE USER '#{merged_name}' #{user_auth_spec(plugin, socket_authentication, password_hash)}", 'system')
    @property_hash[:ensure] = :present
    @property_hash[:plugin] = plugin
    @property_hash[:password_hash] = password_hash
    @property_hash[:socket_authentication] = socket_authentication

    # rubocop:disable Layout/LineLength
    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6')
      self.class.mysql_caller("ALTER USER IF EXISTS '#{merged_name}' WITH MAX_USER_CONNECTIONS #{max_user_connections} MAX_CONNECTIONS_PER_HOUR #{max_connections_per_hour} MAX_QUERIES_PER_HOUR #{max_queries_per_hour} MAX_UPDATES_PER_HOUR #{max_updates_per_hour}", 'system')
    else
      self.class.mysql_caller("GRANT USAGE ON *.* TO '#{merged_name}' WITH MAX_USER_CONNECTIONS #{max_user_connections} MAX_CONNECTIONS_PER_HOUR #{max_connections_per_hour} MAX_QUERIES_PER_HOUR #{max_queries_per_hour} MAX_UPDATES_PER_HOUR #{max_updates_per_hour}", 'system')
    end
    # rubocop:enable Layout/LineLength
    @property_hash[:max_user_connections] = max_user_connections
    @property_hash[:max_connections_per_hour] = max_connections_per_hour
    @property_hash[:max_queries_per_hour] = max_queries_per_hour
    @property_hash[:max_updates_per_hour] = max_updates_per_hour

    merged_tls_options = tls_options.join(' AND ')
    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      self.class.mysql_caller("ALTER USER '#{merged_name}' REQUIRE #{merged_tls_options}", 'system')
    else
      self.class.mysql_caller("GRANT USAGE ON *.* TO '#{merged_name}' REQUIRE #{merged_tls_options}", 'system')
    end
    @property_hash[:tls_options] = tls_options

    exists? ? (return true) : (return false)
  end

  def destroy
    # (MODULES-3539) Allow @ in username
    merged_name = @resource[:name].reverse.sub('@', "'@'").reverse
    if_exists = if newer_than('mysql' => '5.7', 'percona' => '5.7', 'mariadb' => '10.1.3')
                  'IF EXISTS '
                else
                  ''
                end

    self.class.mysql_caller("DROP USER #{if_exists}'#{merged_name}'", 'system')

    @property_hash.clear
    exists? ? (return false) : (return true)
  end

  def exists?
    @property_hash[:ensure] == :present || false
  end

  ##
  ## MySQL user properties
  ##

  # Generates method for all properties of the property_hash
  mk_resource_methods

  def password_hash=(string)
    merged_name = self.class.cmd_user(@resource[:name])
    plugin = @resource.value(:plugin)

    # We have a fact for the mysql version ...
    if (!mysqld_version.nil? && newer_than('mariadb' => '10.1.21') && plugin == 'ed25519') ||
       (!mysqld_version.nil? && newer_than('mariadb' => '11.6') && plugin == 'parsec')
      raise ArgumentError, _('ed25519 hash should be 43 bytes long.') unless string.length == 43 or plugin != 'ed25519'
      raise ArgumentError, _('parsec hash should be 71 bytes long.') unless string.length == 71 or plugin != 'parsec'

      update_auth(plugin, @resource[:socket_authentication], string)
    elsif !mysqld_version.nil? && newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      raise ArgumentError, _('Only mysql_native_password (*ABCD...XXX) hashes are supported.') unless %r{^\*|^$}.match?(string)

      update_auth(plugin, @resource[:socket_authentication], string)
    else
      # default ... if mysqld_version does not work
      self.class.mysql_caller("SET PASSWORD FOR #{merged_name} = '#{string}'", 'system')
    end

    (password_hash == string) ? (return true) : (return false)
  end

  def max_user_connections=(int)
    merged_name = self.class.cmd_user(@resource[:name])
    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      self.class.mysql_caller("ALTER USER #{merged_name} WITH MAX_USER_CONNECTIONS #{int}", 'system').chomp
    else
      self.class.mysql_caller("GRANT USAGE ON *.* TO #{merged_name} WITH MAX_USER_CONNECTIONS #{int}", 'system').chomp
    end
    (max_user_connections == int) ? (return true) : (return false)
  end

  def max_connections_per_hour=(int)
    merged_name = self.class.cmd_user(@resource[:name])
    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      self.class.mysql_caller("ALTER USER #{merged_name} WITH MAX_CONNECTIONS_PER_HOUR #{int}", 'system').chomp
    else
      self.class.mysql_caller("GRANT USAGE ON *.* TO #{merged_name} WITH MAX_CONNECTIONS_PER_HOUR #{int}", 'system').chomp
    end
    (max_connections_per_hour == int) ? (return true) : (return false)
  end

  def max_queries_per_hour=(int)
    merged_name = self.class.cmd_user(@resource[:name])
    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      self.class.mysql_caller("ALTER USER #{merged_name} WITH MAX_QUERIES_PER_HOUR #{int}", 'system').chomp
    else
      self.class.mysql_caller("GRANT USAGE ON *.* TO #{merged_name} WITH MAX_QUERIES_PER_HOUR #{int}", 'system').chomp
    end
    (max_queries_per_hour == int) ? (return true) : (return false)
  end

  def max_updates_per_hour=(int)
    merged_name = self.class.cmd_user(@resource[:name])
    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      self.class.mysql_caller("ALTER USER #{merged_name} WITH MAX_UPDATES_PER_HOUR #{int}", 'system').chomp
    else
      self.class.mysql_caller("GRANT USAGE ON *.* TO #{merged_name} WITH MAX_UPDATES_PER_HOUR #{int}", 'system').chomp
    end
    (max_updates_per_hour == int) ? (return true) : (return false)
  end

  def plugin=(string)
    update_auth(string, @resource[:socket_authentication], @resource[:password_hash])
  end

  def socket_authentication=(value)
    update_auth(@resource[:plugin], value, @resource[:password_hash])
  end

  def update_auth(_plugin, _socket_authentication, _password_hash)
    merged_name = self.class.cmd_user(@resource[:name])

    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      sql = "ALTER USER #{merged_name} #{user_auth_spec(_plugin, _socket_authentication, _password_hash)}"
    else
      if socket_authentication_spec != '' && password_plugin_spec != ''
        warning('Cannot specify multiple authentication plugins with this MySQL version, ignoring socket_authentication.')
      end
      _plugin = socket_auth_plugin if _plugin.nil? && _password_hash.nil? && _socket_authentication == :true
      # See https://bugs.mysql.com/bug.php?id=67449
      sql = "UPDATE mysql.user SET plugin = '#{_plugin}'"
      sql += ((_plugin == 'mysql_native_password') ? ", password = '#{_password_hash}'" : ", password = ''")
      sql += " WHERE CONCAT(user, '@', host) = '#{@resource[:name]}'; FLUSH PRIVILEGES"
    end

    self.class.mysql_caller(sql, 'system')
    (plugin == _plugin && socket_authentication == _socket_authentication && password_hash == _password_hash) ? (return true) : (return false)
  end

  def user_auth_spec(_plugin, _socket_authentication, _password_hash)
    raise ArgumentError, _('You must specify at least one of plugin, password_hash or socket_authentication') \
      if _plugin.nil? && _password_hash.nil? && _socket_authentication != :true

    socket_authentication_spec = _socket_authentication == :true ? socket_auth_plugin : ''
    if !_password_hash.nil?
      _plugin = 'mysql_native_password' if _plugin.nil?
      password_plugin_spec = "'#{_plugin}' AS '#{_password_hash}'"
      if mysqld_type == 'mariadb'
        socket_authentication_spec = ' OR ' + socket_authentication_spec if socket_authentication_spec != ''
      elsif socket_authentication_spec != ''
        socket_authentication_spec = ''
        warning('MySQL does not support specifying multiple authentication plugins, ignoring socket_authentication.')
      end
    elsif (_plugin.nil? || _plugin == socket_auth_plugin) && _socket_authentication == :true
      socket_authentication_spec = ''
      password_plugin_spec = "'#{_plugin}'"
    elsif !_plugin.nil?
      password_plugin_spec = "'#{_plugin}'"
    else
      password_plugin_spec = ''
    end

    return "IDENTIFIED WITH #{password_plugin_spec}#{socket_authentication_spec}"
  end

  def tls_options=(array)
    merged_name = self.class.cmd_user(@resource[:name])
    merged_tls_options = array.join(' AND ')
    if newer_than('mysql' => '5.7.6', 'percona' => '5.7.6', 'mariadb' => '10.2.0')
      self.class.mysql_caller("ALTER USER #{merged_name} REQUIRE #{merged_tls_options}", 'system')
    else
      self.class.mysql_caller("GRANT USAGE ON *.* TO #{merged_name} REQUIRE #{merged_tls_options}", 'system')
    end

    (tls_options == array) ? (return true) : (return false)
  end

  def self.parse_tls_options(ssl_type, ssl_cipher, x509_issuer, x509_subject)
    case ssl_type
    when 'ANY'
      ['SSL']
    when 'X509'
      ['X509']
    when 'SPECIFIED'
      options = []
      options << "CIPHER '#{ssl_cipher}'" if !ssl_cipher.nil? && !ssl_cipher.empty?
      options << "ISSUER '#{x509_issuer}'" if !x509_issuer.nil? && !x509_issuer.empty?
      options << "SUBJECT '#{x509_subject}'" if !x509_subject.nil? && !x509_subject.empty?
      options
    else
      ['NONE']
    end
  end
end
