#!/usr/bin/perl -w
use Net::UCP;
use Data::Dumper;

$ucp = Net::UCP->new(FAKE => 1);
my $smsc_message = $ARGV[0];
$ref_msg = $ucp->parse_message($smsc_message);
print Dumper($ref_msg);
