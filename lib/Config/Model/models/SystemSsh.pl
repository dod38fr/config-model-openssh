[
  {
    'author' => [
      'Dominique Dumont'
    ],
    'class_description' => 'Configuration class used by L<Config::Model> to edit or 
validate /etc/ssh/ssh_config (as root)
',
    'copyright' => [
      '2013 Dominique Dumont'
    ],
    'include' => [
      'Ssh'
    ],
    'license' => 'LGPL2',
    'name' => 'SystemSsh',
    'rw_config' => {
      'backend' => 'OpenSsh::Ssh',
      'config_dir' => '/etc/ssh',
      'file' => 'ssh_config',
      'os_config_dir' => {
        'darwin' => '/etc'
      }
    }
  }
]
;

