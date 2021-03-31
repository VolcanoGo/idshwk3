global IP_agent_table: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    local sourceIP: addr = c$id$orig_h;
    if (name == "USER-AGENT")
    {
        local user_agent: string = to_lower(value);
        if (sourceIP in IP_agent_table)
        {
            add IP_agent_table[sourceIP][user_agent];
        }
        else
        {
            IP_agent_table[sourceIP] = set(user_agent);
        }
    }
}

event zeek_done()
{
    for (temp in IP_agent_table)
    {
        if (|IP_agent_table[temp]| >= 3)
        {
            print fmt("%s is a proxy", temp);
        }
    }
}