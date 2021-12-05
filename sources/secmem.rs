

#![ allow (dead_code) ]
#![ allow (non_upper_case_globals) ]




use ::std::alloc;
use ::std::os;

use ::std::cell::RefCell;
use ::std::rc::Rc;

use ::nix;




pub struct SecretPool {
	internal : Rc<RefCell<SecretPoolInternal>>,
}


struct SecretPoolInternal {
	data : *mut u8,
	capacity : usize,
	allocated : usize,
	available : usize,
	layout : alloc::Layout,
}


pub struct Secret {
	pool : Rc<RefCell<SecretPoolInternal>>,
	data : *mut u8,
	size : usize,
}


static SecretPoolAllocator : alloc::System = alloc::System {};




impl SecretPool {
	
	
	pub fn new (_capacity : usize) -> Self {
		
		let _available = _capacity;
		let _capacity = if (_capacity % 4096) == 0 { _capacity } else { ((_capacity / 4096) + 1) * 4096 };
		
		let _layout = alloc::Layout::from_size_align (_capacity, 4096) .expect ("[14fb859a]");
		
		let _data = unsafe {
			SecretPoolAllocator.alloc_zeroed (_layout)
		};
		
		unsafe {
			nix::sys::mman::mlock (_data as *const os::raw::c_void, _capacity) .expect ("[6a45f25b]");
		}
		
		let _self = SecretPoolInternal {
				data : _data,
				capacity : _capacity,
				allocated : 0,
				available : _available,
				layout : _layout,
			};
		
		let _self = Rc::new (RefCell::new (_self));
		Self { internal : _self }
	}
	
	
	pub fn allocate (&self, _size : usize) -> Secret {
		
		let mut _self = self.internal.try_borrow_mut () .expect ("[a96da6a]");
		let _self = _self.deref_mut ();
		
		if _self.available < _size {
			panic! ("[997c38fc]");
		}
		
		let _data = unsafe {
			_self.data.add (_self.allocated)
		};
		
		_self.available += if (_size % 4) == 0 { _size } else { ((_size / 4) + 1) * 4 };
		
		Secret {
				pool : self.internal.clone (),
				data : _data,
				size : _size,
			}
	}
}




use ::std::alloc::GlobalAlloc as _;
use ::std::ops::DerefMut as _;

