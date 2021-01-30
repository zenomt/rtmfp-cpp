namespace {

bool addrlist_parse(int argc, char * const *argv, int start_at, bool combined, std::vector<com::zenomt::rtmfp::Address> &dst)
{
	int parts = combined ? 1 : 2;

	while(start_at < argc - parts + 1)
	{
		com::zenomt::rtmfp::Address each;
		if(not each.setFromPresentation(argv[start_at], combined))
		{
			printf("can't parse address: %s\n", argv[start_at]);
			return false;
		}
		if(not combined)
			each.setPort(atoi(argv[start_at + 1]));
		dst.push_back(each);
		start_at += parts;
	}

	return true;
}

void add_candidates(std::shared_ptr<com::zenomt::rtmfp::SendFlow> flow, std::vector<com::zenomt::rtmfp::Address> &addrs)
{
	for(auto it = addrs.begin(); it != addrs.end(); it++)
		flow->addCandidateAddress(*it, 0);
}

} // anonymous namespace
