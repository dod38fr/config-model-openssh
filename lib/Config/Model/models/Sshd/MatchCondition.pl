use strict;
use warnings;

return [
  {
    'author' => [
      'Dominique Dumont'
    ],
    'class_description' => 'Conidtion to apply to identify matched items inside 
a sshd_config match block.',
    'copyright' => [
      '2009-2011 Dominique Dumont'
    ],
    'element' => [
      'User',
      {
        'description' => 'Define the User criteria of a conditional block. The value of this field is a pattern that is tested against user name.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Group',
      {
        'description' => 'Define the Group criteria of a conditional block. The value of this field is a pattern that is tested against group name.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Host',
      {
        'description' => 'Define the Host criteria of a conditional block. The value of this field is a pattern that is tested against host name.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Address',
      {
        'description' => 'Define the Address criteria of a conditional block. The value of this field is a pattern that is tested against the address of the incoming connection.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      }
    ],
    'license' => 'LGPL2',
    'name' => 'Sshd::MatchCondition'
  }
]
;

