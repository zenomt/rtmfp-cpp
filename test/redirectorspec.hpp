namespace {

using Address = com::zenomt::rtmfp::Address;
using RedirectorClient = com::zenomt::rtmfp::RedirectorClient;

bool parse_redirector_spec(const std::string &spec, std::string &outName, std::vector<Address> &outAddresses)
{
	outName = "";
	size_t pos = spec.find('@');
	if(std::string::npos == pos)
		return false;
	outName = spec.substr(0, pos);
	pos++; // move past '@'

	outAddresses.clear();

	auto remainder = spec.substr(pos);
	while(true)
	{
		pos = remainder.find(',');

		Address tmp;
		if(not tmp.setFromPresentation(remainder.substr(0, pos).c_str()))
			return false;
		outAddresses.push_back(tmp);

		if(std::string::npos == pos)
			break;
		remainder = remainder.substr(pos + 1);
	}

	return not outAddresses.empty();
}

bool parse_redirector_spec(const std::string &spec, std::map<std::string, std::vector<Address>> &outSpecs)
{
	std::string hostname;
	std::vector<Address> addresses;
	if(not parse_redirector_spec(spec, hostname, addresses))
		return false;

	outSpecs[hostname] = addresses;
	return true;
}

void config_redirector_client(RedirectorClient *client, const std::map<std::string, std::string> &auths, const std::vector<Address> &redirAddrs, const std::vector<Address> &advertiseAddrs, bool advertiseReflexive)
{
	for(auto it = auths.begin(); it != auths.end(); it++)
		client->addSimpleAuth(it->first.c_str(), it->second.c_str());
	for(auto it = redirAddrs.begin(); it != redirAddrs.end(); it++)
		client->addRedirectorAddress(*it);
	for(auto it = advertiseAddrs.begin(); it != advertiseAddrs.end(); it++)
		client->addAdditionalAddress(*it);
	client->setAdvertiseReflexiveAddress(advertiseReflexive);
}

} // anonymous namespace
