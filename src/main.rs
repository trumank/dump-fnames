use anyhow::{Context, Result};
use patternsleuth::resolvers::{impl_try_collector, unreal::fname::FNamePool};
use read_process_memory::{copy_address, ProcessHandle};

fn find_pool(pid: i32) -> Result<usize> {
    impl_try_collector! {
        #[derive(Debug, PartialEq)]
        struct Resolution {
            name_pool: FNamePool,
        }
    }

    let exe = patternsleuth::process::external::read_image_from_pid(pid)?;
    let resolution = exe.resolve(Resolution::resolver())?;
    Ok(resolution.name_pool.0)
}

fn main() -> Result<()> {
    let pid = std::env::args()
        .nth(1)
        .context("expected PID as first arg")?
        .parse::<read_process_memory::Pid>()
        .context("could not parse PID")?;
    let name_pool = find_pool(pid as i32)?;
    let block_len = 0x20000;

    let handle: ProcessHandle = pid.try_into().unwrap();

    let block_count =
        u32::from_le_bytes(copy_address(name_pool + 8, 4, &handle)?.try_into().unwrap()) as usize;

    for (block_index, chunk) in copy_address(name_pool + 0x10, (1 + block_count) * 8, &handle)?
        .chunks(8)
        .enumerate()
    {
        let ptr = u64::from_le_bytes(chunk.try_into().unwrap());

        let chunk = copy_address(ptr as usize, block_len, &handle)?;

        let mut bytes = chunk.iter();
        bytes.next();
        bytes.next();

        //std::fs::write(format!("chunk{block}.bin"), &chunk)?;

        let mut possible = vec![];
        let mut i = 2;
        // assume FNames cannot contain chars < 32
        while let Some(next) = bytes.position(|b| !(32..).contains(b)) {
            possible.push((i - 2)..(i + next + 1));
            i += next + 1;
        }

        #[derive(Debug)]
        struct FName {
            value: u32,
            string: String,
        }

        let mut validated = vec![];
        for range in &possible {
            let base = range.start;
            let p = &chunk[range.clone()];
            for i in 2..p.len() {
                let index = base + i - 2;
                if index % 2 != 0 {
                    // FNames have an alignment of 2
                    continue;
                }
                let value = ((block_index << 16) | (index / 2)) as u32;

                let header = ((p[i - 1] as u16) << 8) + p[i - 2] as u16;
                let len = (header >> 6) as usize;
                let is_wide = (header & 1) != 0;
                if is_wide {
                    //todo!();
                }
                if len > 0 && !is_wide && i + len < p.len() {
                    let Ok(name) = String::from_utf8(p[i..(i + len)].to_vec()) else {
                        continue;
                    };
                    validated.push(FName {
                        value,
                        string: name,
                    });
                }
            }
        }

        for v in validated {
            println!(
                "{} {:>20} {}",
                v.value,
                cityhasher::hash_with_seed::<u64>(v.string.to_ascii_uppercase(), 0),
                v.string
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    #[test]
    fn test_hash() {
        assert_eq!(
            549208615835106585,
            cityhasher::hash_with_seed::<u64>(
                "FNiagaraRibbonVertexFactory".to_ascii_uppercase(),
                0
            )
        );
    }
}
