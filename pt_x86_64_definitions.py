from pt_common import *

class PML4_Entry():
    def __init__(self, value, index):
        self.present = is_present(value)
        self.writeable = is_writeable(value)
        self.supervisor = is_supervisor(value)
        self.writeback = is_writeback(value)
        self.cacheable = is_cacheable(value)
        self.accessed = is_accessed(value)
        self.available = is_available(value)
        self.nx = is_nx(value)
        self.pdp = get_pdp_base(value)
        self.raw = value
        self.virt_part = (index << 39)

    def __str__(self):
        res = (f"{hex(self.pdp)}: "
               f"P:{int(self.present)} "
               f"W:{int(self.writeable)} "
               f"S:{int(self.supervisor)} "
               f"WB:{int(self.writeback)} "
               f"UC:{int(not self.cacheable)} "
               f"A:{int(self.accessed)} "
               f"AVL:{int(self.available)} "
               f"NX:{int(self.nx)}")
        return res

class PDP_Entry():
    def __init__(self, value, parent_va, index):
        self.present = is_present(value)
        self.writeable = is_writeable(value)
        self.supervisor = is_supervisor(value)
        self.writeback = is_writeback(value)
        self.cacheable = is_cacheable(value)
        self.accessed = is_accessed(value)
        self.virt_part = (index << 30) | parent_va
        self.large_page = is_large_page(value) # This means it's a leaf
        if self.large_page:
            self.dirty = is_dirty(value)
            self.glob = True
            self.pd = extract_no_shift(value, 30, 51)
        else:
            self.pd = get_pdp_base(value)
        self.nx = is_nx(value)

    def __str__(self):
        res = (f"{hex(self.pd)}: "
               f"P:{int(self.present)} "
               f"W:{int(self.writeable)} "
               f"S:{int(self.supervisor)} "
               f"WB:{int(self.writeback)} "
               f"UC:{int(not self.cacheable)} "
               f"A:{int(self.accessed)} ")
        if self.large_page:
                res += (f"D:{int(self.dirty)} "
                        f"G:{int(self.glob)} "
                        f"NX:{int(self.nx)}")
        return res

class PD_Entry():
    def __init__(self, value, parent_va, index, pde_shift):
        self.present = is_present(value)
        self.writeable = is_writeable(value)
        self.supervisor = is_supervisor(value)
        self.writeback = is_writeback(value)
        self.cacheable = is_cacheable(value)
        self.accessed = is_accessed(value)
        self.virt_part = (index << pde_shift) | parent_va
        self.big_page = is_big_page(value) # This means it's a leaf
        if self.big_page:
            self.dirty = is_dirty(value)
            self.glob = True
            self.pat = is_pat(value)
            # TODO
            self.pt = extract_no_shift(value, 20, 51)
        else:
            self.pt = get_pdp_base(value)
        self.page_size = 1 << pde_shift
        self.nx = is_nx(value)

    def __str__(self):
        res = (f"{hex(self.pt)}: "
               f"P:{int(self.present)} "
               f"W:{int(self.writeable)} "
               f"S:{int(self.supervisor)} "
               f"WB:{int(self.writeback)} "
               f"UC:{int(not self.cacheable)} "
               f"A:{int(self.accessed)} ")
        if self.big_page:
                res += (f"D:{int(self.dirty)} "
                        f"G:{int(self.glob)} "
                        f"NX:{int(self.nx)}")
        return res

class PT_Entry():
    def __init__(self, value, parent_va, index):
        self.present = is_present(value)
        self.writeable = is_writeable(value)
        self.supervisor = is_supervisor(value)
        self.writeback = is_writeback(value)
        self.cacheable = is_cacheable(value)
        self.accessed = is_accessed(value)
        self.dirty = is_dirty(value)
        self.glob = True
        self.pat = is_pat(value)
        self.pt = extract_no_shift(value, 12, 51)
        self.virt = (index << 12) | parent_va
        self.nx = is_nx(value)

    def __str__(self):
        res = (f"{hex(self.pt)}: "
               f"P:{int(self.present)} "
               f"W:{int(self.writeable)} "
               f"S:{int(self.supervisor)} "
               f"WB:{int(self.writeback)} "
               f"UC:{int(not self.cacheable)} "
               f"A:{int(self.accessed)} "
               f"D:{int(self.dirty)} "
               f"PAT:{int(self.pat)} "
               f"G:{int(self.glob)} "
               f"NX:{int(self.nx)}")
        return res

def create_page_from_pte(pte: PT_Entry) -> Page:
    page = Page()
    page.va = make_canonical(pte.virt)
    page.page_size = 4096
    page.w = pte.writeable
    page.x = not pte.nx
    page.s = pte.supervisor
    page.uc = not pte.cacheable
    page.wb = pte.writeback
    page.phys = [pte.pt]
    page.sizes = [page.page_size]
    return page

def create_page_from_pde(pde: PD_Entry) -> Page:
    page = Page()
    page.va = make_canonical(pde.virt_part)
    page.page_size = pde.page_size
    page.w = pde.writeable
    page.x = not pde.nx
    page.s = pde.supervisor
    page.uc = not pde.cacheable
    page.wb = pde.writeback
    page.phys = [pde.pt]
    page.sizes = [page.page_size]
    return page

def create_page_from_pdpe(pdpe: PDP_Entry) -> Page:
    page = Page()
    page.va = make_canonical(pdpe.virt_part)
    page.page_size = 1024 * 1024 * 1024
    page.w = pdpe.writeable
    page.x = not pdpe.nx
    page.s = pdpe.supervisor
    page.uc = not pdpe.cacheable
    page.wb = pdpe.writeback
    page.phys = [pdpe.pd]
    page.sizes = [page.page_size]
    return page

def is_present(addr):
    return (addr & 0x1) != 0

def is_writeable(addr):
    return (addr & 0x2) != 0

def is_supervisor(addr):
    return (addr & 0x4) == 0

def is_writeback(addr):
    return (addr & 0x8) == 0

def is_cacheable(addr):
    return (addr & 0x10) == 0

def is_accessed(addr):
    return (addr & 0x10) == 1

def is_dirty(addr):
    return ((addr >> 6) & 0x1) == 0

def is_available(addr):
    return ((addr >> 9) & 0x3) != 0

def is_nx(addr):
    return (addr & (1<<63)) != 0

def get_pdp_base(addr):
    return extract_no_shift(addr, 12, 51)

# One gigabyte-large page.
def is_large_page(addr):
    return (addr >> 0x7) & 0x1

# Either two-mb- or four-mb-large page.
def is_big_page(addr):
    return (addr >> 7) & 0x1

def is_pat(addr):
    return (addr >> 12) & 0x1

def is_global(addr):
    return (addr >> 0x8) & 0x1

def is_pat(addr):
    return (addr >> 12) & 0x1

def rwxs_semantically_similar(p1: Page, p2: Page) -> bool:
    return p1.w == p2.w and p1.x == p2.x and p1.s == p2.s and p1.wb == p2.wb and p1.uc == p2.uc

