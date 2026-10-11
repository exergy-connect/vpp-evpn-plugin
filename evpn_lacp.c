/* SPDX-License-Identifier: Apache-2.0
 * Explicit LACP actor port numbers for a shared EVPN Ethernet Segment system.
 * Built into evpn_plugin against the runtime's own VPP development headers.
 */
#include <vnet/vnet.h>
#include <vnet/bonding/node.h>

static clib_error_t *
evpn_lacp_port_id (vlib_main_t *vm, unformat_input_t *input,
                   vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  bond_main_t *bm = &bond_main;
  u32 sw_if_index, port_id;
  member_if_t *member;
  bond_if_t *bond, *other_bond;
  u32 *member_index;

  if (!unformat (input, "%U %u", unformat_vnet_sw_interface, vnm,
                 &sw_if_index, &port_id)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || port_id == 0 || port_id > 65535)
    return clib_error_return (0, "expected <member-interface> <port-id 1..65535>");
  member = bond_get_member_by_sw_if_index (sw_if_index);
  if (!member || !member->lacp_enabled)
    return clib_error_return (0, "interface is not a LACP bond member");
  if (vnet_sw_interface_is_admin_up (vnm, sw_if_index))
    return clib_error_return (0, "bring the member interface down before changing its LACP port-id");
  bond = bond_get_bond_if_by_dev_instance (member->bif_dev_instance);

  /* Port numbers must be unique across bonds using the same actor system. */
  pool_foreach (other_bond, bm->interfaces)
    {
      if (memcmp (bond->hw_address, other_bond->hw_address, 6))
        continue;
      vec_foreach (member_index, other_bond->members)
        {
          member_if_t *other = bond_get_member_by_sw_if_index (*member_index);
          if (other && other != member && other->lacp_enabled
              && clib_net_to_host_u16 (other->actor_admin.port_number) == port_id)
            return clib_error_return (0, "LACP port-id %u is already in use", port_id);
        }
    }
  bond->port_number_bitmap = clib_bitmap_set (
    bond->port_number_bitmap,
    clib_net_to_host_u16 (member->actor_admin.port_number) - 1, 0);
  bond->port_number_bitmap = clib_bitmap_set (
    bond->port_number_bitmap, port_id - 1, 1);
  member->actor_admin.port_number = clib_host_to_net_u16 (port_id);
  member->actor.port_number = member->actor_admin.port_number;
  /* The normal member admin-up callback resets LACP state machines from the
   * updated actor_admin, preserving this number through future link flaps. */
  return 0;
}

VLIB_CLI_COMMAND (evpn_lacp_port_id_command, static) = {
  .path = "set interface lacp port-id",
  .short_help = "set interface lacp port-id <member-interface> <port-id 1..65535>",
  .function = evpn_lacp_port_id,
};
