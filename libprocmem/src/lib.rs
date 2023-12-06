
#[allow(dead_code)]

use std::fs::File;
use std::io::Error;
use std::io::{BufReader, BufRead};
use nix::unistd::Pid;


pub const READ_PERM:  u8 = 1 << 0;
pub const WRITE_PERM: u8 = 1 << 1;
pub const EXEC_PERM:  u8 = 1 << 2;
pub const SHARE_PERM: u8 = 1 << 3;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MemAddress(usize);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Perm(pub u8);



/// Represents a single line in the `/proc/<pid>/maps` file which describes a region
#[derive(Debug, Clone)]
pub struct Region {
    pub start_address: usize,
    pub end_address:   usize,
    pub perms:         u8,
    pub offset:        usize,
    pub device:        String,
    pub inode:         usize,
    pub pathname:      String,
}


impl Region {

    /// Parse a line from the `/proc/<pid>/maps` file and return a Region Struct
    pub fn from_string(line: &str) -> Result<Region, Error> {
        // parse the line based on spaces
        let mut line = line.split(' ');

        // parse start and end address
        let addresses = line.next()
            .unwrap_or_else(|| {
            "Failed to get addresses"
            })
            .split('-');

        let addrs: Vec<usize> = addresses.map(|addr| {
            usize::from_str_radix(addr, 16).unwrap()
        }).collect();

        // parse perms
        let perm_string = line.next()
            .unwrap_or_else(|| {
                "Failed to get perms"
            })
            .chars();
        let mut perm = 0;

        for p in perm_string {
            match p {
                'r' => { perm |= READ_PERM },
                'w' => { perm |= WRITE_PERM },
                'x' => { perm |= EXEC_PERM },
                'p' => { perm |= SHARE_PERM },
                 _   => (),
            }
        }

        let offset = line.next()
            .unwrap_or_else(|| {
                "failed to get offset"
            });

        let offset = usize::from_str_radix(offset, 16).unwrap();

        let device = line.next()
            .unwrap_or_else(|| {
                "failed to get device"
            })
            .clone();

        let inode = line.next()
            .unwrap_or_else(|| {
                "failed to get inode"
            });
        let inode = usize::from_str_radix(inode, 10).unwrap();

        let pathname = line.last();
        let pathname = match pathname {
            Some(name) => name,
            None => "",
        };


        Ok(Region {
            start_address : addrs[0],
            end_address   : addrs[1],
            perms         : perm,
            offset        : offset,
            device        : String::from(device),
            inode         : inode,
            pathname      : String::from(pathname),
        })
    }
}



pub struct Proc {
    pub pid: Pid,
    pub regions: Vec<Region>

}


impl Proc {

    pub fn new(pid: Pid) -> Result<Self, Error> {

        let regions = Self::optain_regions(pid)?;
        Ok(Proc {
            pid: pid,
            regions: regions,
        })

    }

    pub fn reset_regions(&mut self) {
        self.regions = Self::optain_regions(self.pid).unwrap();
    }

    pub fn optain_regions(pid: Pid) -> Result<Vec<Region>, Error>{

        let mut regions: Vec<Region> = Vec::new();
        let maps_file = File::open(format!("/proc/{}/maps", pid))?;

        let reader = BufReader::new(maps_file);

        for line in reader.lines() {
            let region = Region::from_string(&line?);
            regions.push(region?);
        }

        Ok(regions)
    }

    pub fn print_regions(&self) {
        for region in self.regions.clone() {
            //println!("{:?}", region);
            println!("{:08x} - {:08x}  {:-4b}", region.start_address, region.end_address, region.perms);
        }
    }

}



#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn region_first_line_test() {
        let region = Region::from_string("57d96022000-557d96024000 r--p 00000000 fd:01 94634132                   /usr/bin/cat").unwrap();

        assert_eq!(region.start_address, 0x57d96022000);
        assert_eq!(region.end_address, 0x557d96024000);
        assert_eq!(region.perms, 9);
        assert_eq!(region.offset, 0);
        assert_eq!(region.device, "fd:01");
        assert_eq!(region.inode, 94634132);
        assert_eq!(region.pathname, "/usr/bin/cat");

    }

    #[test]
    fn region_second_line_test() {
        let region = Region::from_string("55f7e27d5000-55f7e27f6000 rw-p 00000000 00:00 0                          [heap]").unwrap();

        assert_eq!(region.start_address, 0x55f7e27d5000);
        assert_eq!(region.end_address, 0x55f7e27f6000);
        assert_eq!(region.perms, 11);
        assert_eq!(region.offset, 0);
        assert_eq!(region.device, "00:00");
        assert_eq!(region.inode, 0);
        assert_eq!(region.pathname, "[heap]");

    }

    #[test]
    fn region_third_line_test() {
        let region = Region::from_string("7f02806ff000-7f0280701000 rw-p 00000000 00:00 0").unwrap();

        assert_eq!(region.start_address, 0x7f02806ff000);
        assert_eq!(region.end_address, 0x7f0280701000);
        assert_eq!(region.perms, 11);
        assert_eq!(region.offset, 0);
        assert_eq!(region.device, "00:00");
        assert_eq!(region.inode, 0);
        assert_eq!(region.pathname, "");
    }



}
