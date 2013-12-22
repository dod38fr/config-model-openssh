[
  {
    'author' => [
      'Dominique Dumont'
    ],
    'class_description' => 'Class to represent a Match block inside a sshd_config file. 

It\'s made of a list of conditions to match and a list of 
parameters to apply to the matched items.',
    'copyright' => [
      '2009-2011 Dominique Dumont'
    ],
    'element' => [
      'Condition',
      {
        'config_class_name' => 'Sshd::MatchCondition',
        'description' => 'Specify the condition (User, Group, Host, Adress) necessary for this Match block to be applied',
        'type' => 'node'
      },
      'Settings',
      {
        'config_class_name' => 'Sshd::MatchElement',
        'description' => 'Defines the sshd_config parameters that will override general settings when all defined User, Group, Host and Address patterns match.',
        'type' => 'node'
      }
    ],
    'license' => 'LGPL2',
    'name' => 'Sshd::MatchBlock'
  }
]
;

