#
# UDT custom Centreon mode: FortiGate DHCP server lease usage.
#
# Reads FORTINET-FORTIGATE-MIB::fgDhcpTable, one row per configured DHCP
# server, and reports how many leases each one has handed out plus the total.
#
# The MIB documents fgDhcpTable as indexed by virtual domain alone, but FortiOS
# returns one row per DHCP server: the index is (vdom, serverId).
#
# SNMP does not publish the size of an address pool, so this reports lease
# counts, never a percentage of the pool. A count on its own says nothing about
# exhaustion, which is why no threshold is set by default: pick one per pool
# from the pool's configured range.
#

package udt::fortinet::fortigate::snmp::mode::check_dhcp_usage;

use base qw(centreon::plugins::templates::counter);

use strict;
use warnings;

my $oid_fgDhcpServerNumber = '.1.3.6.1.4.1.12356.101.23.1.1';
my $oid_fgDhcpLeaseUsage   = '.1.3.6.1.4.1.12356.101.23.2.1.1.2';

sub set_counters {
    my ($self, %options) = @_;

    $self->{maps_counters_type} = [
        { name => 'global', type => 0, cb_prefix_output => 'prefix_global_output' },
        { name => 'server', type => 1, cb_prefix_output => 'prefix_server_output',
          message_multiple => 'All DHCP servers are ok', skipped_code => { -10 => 1 } }
    ];

    $self->{maps_counters}->{global} = [
        { label => 'total-leases', nlabel => 'dhcp.leases.total.count', set => {
                key_values => [ { name => 'leases' } ],
                output_template => 'leases in use: %s',
                perfdatas => [ { label => 'total_leases', template => '%s', min => 0 } ]
            }
        },
        { label => 'servers', nlabel => 'dhcp.servers.configured.count', set => {
                key_values => [ { name => 'servers' } ],
                output_template => 'servers configured: %s',
                perfdatas => [ { label => 'servers', template => '%s', min => 0 } ]
            }
        }
    ];

    $self->{maps_counters}->{server} = [
        { label => 'leases', nlabel => 'dhcp.server.leases.count', set => {
                key_values => [ { name => 'leases' }, { name => 'display' } ],
                output_template => 'leases in use: %s',
                perfdatas => [
                    { label => 'leases', template => '%s',
                      min => 0, label_extra_instance => 1, instance_use => 'display' }
                ]
            }
        }
    ];
}

sub prefix_global_output {
    my ($self, %options) = @_;

    return 'DHCP ';
}

sub prefix_server_output {
    my ($self, %options) = @_;

    return "DHCP server '" . $options{instance_value}->{display} . "' ";
}

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options);
    bless $self, $class;

    $options{options}->add_options(arguments => {
        'filter-server-id:s' => { name => 'filter_server_id' }
    });

    return $self;
}

sub manage_selection {
    my ($self, %options) = @_;

    my $snmp_result = $options{snmp}->get_multiple_table(
        oids => [
            { oid => $oid_fgDhcpServerNumber },
            { oid => $oid_fgDhcpLeaseUsage }
        ],
        return_type  => 1,
        nothing_quit => 1
    );

    $self->{global} = {
        leases  => 0,
        servers => $snmp_result->{ $oid_fgDhcpServerNumber . '.0' }
    };
    $self->{server} = {};

    # One row per DHCP server, indexed by (vdom, serverId).
    my $selected = {};
    foreach my $oid (keys %$snmp_result) {
        next if ($oid !~ /^$oid_fgDhcpLeaseUsage\.(\d+)\.(\d+)$/);
        my ($vdom, $server_id) = ($1, $2);

        if (defined($self->{option_results}->{filter_server_id}) && $self->{option_results}->{filter_server_id} ne '' &&
            $server_id !~ /$self->{option_results}->{filter_server_id}/) {
            $self->{output}->output_add(long_msg => "skipping DHCP server '" . $server_id . "'.", debug => 1);
            next;
        }

        $selected->{$vdom . '.' . $server_id} = {
            vdom      => $vdom,
            server_id => $server_id,
            leases    => $snmp_result->{$oid}
        };
    }

    # Server ids repeat across virtual domains, so only name the domain when
    # there is more than one.
    my %vdoms = map { $_->{vdom} => 1 } values %$selected;
    my $show_vdom = scalar(keys %vdoms) > 1 ? 1 : 0;

    foreach my $instance (keys %$selected) {
        my $entry = $selected->{$instance};
        $self->{server}->{$instance} = {
            display => $show_vdom
                ? 'vdom ' . $entry->{vdom} . ' server ' . $entry->{server_id}
                : 'server ' . $entry->{server_id},
            leases => $entry->{leases}
        };
        $self->{global}->{leases} += $entry->{leases};
    }

    if (scalar(keys %{$self->{server}}) <= 0) {
        $self->{output}->add_option_msg(short_msg => 'No DHCP server found.');
        $self->{output}->option_exit();
    }
}

1;

__END__

=head1 MODE

Check the DHCP servers of a FortiGate: how many leases each one has handed out,
and the total across all of them.

SNMP does not publish the size of an address pool, so this cannot report a
percentage of the pool. Thresholds are lease counts and have no default: set
one per pool from that pool's configured range, or watch the perfdata for
growth.

=over 8

=item B<--filter-server-id>

Filter by DHCP server id (can be a regexp).

=item B<--warning-*> B<--critical-*>

Thresholds. Can be: 'total-leases', 'servers', 'leases'.

=back

=cut
