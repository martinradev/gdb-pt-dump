from pt_x86_64_definitions import *
from pt_common import *

def parse_pml4(addr):
    entries = []
    values = read_page(addr)
    for u, value in enumerate(values):
        if (value & 0x1) != 0: # Page must be present
            entry = PML4_Entry(value, u)
            entries.append(entry)
    return entries

def parse_pml4es(pml4es):
    entries = []
    for pml4e in pml4es:
        pdpe = parse_pdp(pml4e)
        entries.extend(pdpe)
    return entries

def parse_pdp(pml4e):
    entries = []
    values = read_page(pml4e.pdp)
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            entry = PDP_Entry(value, pml4e.virt_part, u)
            entries.append(entry)
    return entries

def parse_pd(pdpe):
    entries = []
    values = read_page(pdpe.pd)
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            entry = PD_Entry(value, pdpe.virt_part, u)
            entries.append(entry)
    return entries

def parse_pdpes(pdpes):
    entries = []
    pages = []
    for pdpe in pdpes:
        if pdpe.one_gig == False:
            pdes = parse_pd(pdpe)
            entries.extend(pdes)
        else:
            page = create_page_from_pdpe(pdpe)
            one_gig_pages.append(page)
    return entries, pages

def parse_pt(pde):
    entries = []
    values = read_page(pde.pt)
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            entry = PT_Entry(value, pde.virt_part, u)
            entries.append(entry)
    return entries

def parse_pdes(pdes):
    entries = []
    pages = []
    for pde in pdes:
        if pde.two_mb == False:
            ptes = parse_pt(pde)
            entries.extend(ptes)
        else:
            page = create_page_from_pde(pde)
            pages.append(page)
    return entries, pages

def parse_and_print_x86_64_table(cache, args, should_print = True):
    pt_addr = None
    if args.addr:
        pt_addr = int(args.addr[0], 16)
    else:
        pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("long")))

    page_ranges = None
    if pt_addr in cache:
        page_ranges = cache[pt_addr]
    else:
        pml4es = parse_pml4(pt_addr)
        pdpes = parse_pml4es(pml4es)
        pdes, one_gig_pages = parse_pdpes(pdpes)
        ptes, two_mb_pages = parse_pdes(pdes)
        small_pages = []
        for pte in ptes:
            small_pages.append(create_page_from_pte(pte))
        page_ranges = optimize(one_gig_pages, two_mb_pages, small_pages, rwxs_semantically_similar)

    # Cache the page table if caching is set.
    # Caching happens before the filter is applied.
    if args.save:
        cache[pt_addr] = page_ranges

    if args.filter:
        filters = []
        for f in args.filter:
            if f == "w":
                filters.append(lambda p: p.w)
            elif f == "_w":
                filters.append(lambda p: not p.w)
            elif f == "x":
                filters.append(lambda p: p.x)
            elif f == "_x":
                filters.append(lambda p: not p.x)
            elif f == "w|x" or f == "x|w":
                filters.append(lambda p: p.x or p.w)
            elif f == "u" or f == "_s":
                filters.append(lambda p: not p.s)
            elif f == "s" or f == "_u":
                filters.append(lambda p: p.s)
            elif f == "ro":
                filters.append(lambda p: not p.x and not p.w)
            elif f == "wb":
                filters.append(lambda p: p.wb)
            elif f == "_wb":
                filters.append(lambda p: not p.wb)
            elif f == "uc":
                filters.append(lambda p: p.uc)
            elif f == "_uc":
                filters.append(lambda p: not p.uc)
            else:
                print(f"Unknown filter: {f}")
                return

        ff = create_compound_filter(filters)
        page_ranges = list(filter(ff, page_ranges))

    if args.range:
        page_ranges = list(filter(lambda page: page.va >= args.range[0] and page.va <= args.range[1], page_ranges))

    if args.has:
        page_ranges = list(filter(lambda page: args.has[0] >= page.va and args.has[0] < page.va + page.page_size, page_ranges))

    if should_print:
        # Compute max len for these varying-len strings in order to print as tabular.
        max_va_len, max_page_size_len = compute_max_str_len(page_ranges)
        conf = PagePrintSettings(va_len = max_va_len, page_size_len = max_page_size_len)
        fmt = f"  {{:>{max_va_len}}} : {{:>{max_page_size_len}}}"
        varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + "   Permissions          " + bcolors.ENDC)
        for page in page_ranges:
            print(page_to_str(page, conf))

    return page_ranges

