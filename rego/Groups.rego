package groups

import data.utils
import future.keywords

LogEvents := utils.GetEvents("groups_logs")

NoGroupsDetails(Groups) := "No Groups found in Organization." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := "Requirement met in all Groups." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := Message if {
    count(Groups) > 0
    Message := concat("", ["Requirement failed in ", concat(", ", Groups), "."])
}

################
# GWS.GROUPS.1 #
################

#
# Baseline GWS.GROUPS.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "GroupsSharingSettingsProto collaboration_policy", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "CLOSED"
}

tests contains {
    "PolicyId": "GWS.GROUPS.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "GroupsSharingSettingsProto collaboration_policy", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "GroupsSharingSettingsProto collaboration_policy", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--


################
# GWS.GROUPS.2 #
################

#
# Baseline GWS.GROUPS.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "GroupsSharingSettingsProto owners_can_allow_external_members"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "GroupsSharingSettingsProto owners_can_allow_external_members"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs":NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "GroupsSharingSettingsProto owners_can_allow_external_members"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# GWS.GROUPS.3 #
################

#
# Baseline GWS.GROUPS.3.1v0.1
#--
NonCompliantOUs3_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--


################
# GWS.GROUPS.4 #
################

#
# Baseline GWS.GROUPS.4.1v0.1
#--

GetFriendlyValue4_1(Value) := " Anyone in the organization can create groups" if {
    Value == "USERS_IN_DOMAIN"
} else := " Anyone on the internet can create groups" if {
    Value = "WORLD"
} else := " Only organization admins can create groups" if {
    Value = "ADMIN_ONLY"
} else := Value

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": concat("", [
        "Permissions for who can create groups is set to", 
        GetFriendlyValue4_1(LastEvent.NewValue)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto who_can_create_groups", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ADMIN_ONLY"
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails":utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "GroupsSharingSettingsProto who_can_create_groups", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails": concat("",[utils.ReportDetailsBoolean(Status),
    GetFriendlyValue4_1(LastEvent.NewValue)]),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "GroupsSharingSettingsProto who_can_create_groups", utils.TopLevelOU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    Status := count(NonCompliantOUs4_1) == 0
}
#--


################
# GWS.GROUPS.5 #
################

#
# Baseline GWS.GROUPS.5.1v0.1
#--
GetFriendlyValue5_1(Value) := " Default permission to view conversation is set to 'Owners Only'." if {
    Value == "OWNERS"
} else := " Default permission to view conversation is set to 'Owners and Managers'." 
if {
    Value = "MANAGERS"
} else := " Default permission to view conversation is set to 'All Group Members'."
if {
    Value = "MEMBERS"
} else := " Default permission to view conversation is set to 'All Organization Users'."
if {
    Value = "DOMAIN_USERS"
} else := " Default permission to view conversation is set to 'Anyone on the internet'."
if {
    Value = "PUBLIC"
} else := Value

NonCompliantOUs5_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "GroupsSharingSettingsProto default_view_topics_access_level", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "MEMBERS"
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "GroupsSharingSettingsProto default_view_topics_access_level"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.1",
    "Criticality": "Should",
    "ReportDetails": concat("", [utils.ReportDetailsBoolean(Status), 
    "<br>", GetFriendlyValue5_1(LastEvent.NewValue)]),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "GroupsSharingSettingsProto default_view_topics_access_level"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    LastEvent := utils.GetLastEvent(Events)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--


################
# GWS.GROUPS.6 #
################

#
# Baseline GWS.GROUPS.6.1v0.1
#--

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue":"No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsNoOU(LogEvents, "GroupsSharingSettingsProto allow_unlisted_groups")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails":utils.ReportDetailsBoolean(Status),
    "ActualValue": {LastEvent.Setting: LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsNoOU(LogEvents, "GroupsSharingSettingsProto allow_unlisted_groups")
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    Status := LastEvent.NewValue == "false"
}
#--

################
# GWS.GROUPS.7 #
################

#
# Baseline GWS.GROUPS.7.1v0.1
#--
NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    Group.whoCanJoin != "CAN_REQUEST_TO_JOIN"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    Group.whoCanViewMembership != "ALL_MEMBERS_CAN_VIEW"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    Group.whoCanViewGroup != "ALL_MEMBERS_CAN_VIEW"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    Group.whoCanModerateMembers != "OWNERS_AND_MANAGERS"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    Group.allowExternalMembers != "false"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    Group.whoCanPostMessage != "ALL_MEMBERS_CAN_POST"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    Group.whoCanContactOwner != "ANYONE_CAN_CONTACT"
}

# if there are no groups, it has to be safe.
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.1",
    "Prerequisites": ["directory/v1/domains/list", "directory/v1/groups/list", "groups-settings/v1/groups/get"],
    "Criticality": "Should",
    "ReportDetails": NoGroupsDetails(Groups),
    "ActualValue": NoGroupsDetails(Groups),
    "RequirementMet": true,
    "NoSuchEvent": false
}
if {
    Groups := {Group.email | some Group in input.group_settings}
    count(Groups) == 0
}

# if there are groups
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.1",
    "Prerequisites": ["directory/v1/domains/list", "directory/v1/groups/list", "groups-settings/v1/groups/get"],
    "Criticality": "Should",
    "ReportDetails": ReportDetailsGroups(NonCompliantGroups7_1),
    "ActualValue": {"NonCompliantGroups": NonCompliantGroups7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Groups := {Group.email | some Group in input.group_settings}
    count(Groups) > 0
    Status := count(NonCompliantGroups7_1) == 0
}
#--