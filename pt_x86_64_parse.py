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
