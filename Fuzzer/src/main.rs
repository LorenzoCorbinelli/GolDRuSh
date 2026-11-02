use std::{
    borrow::Cow,
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    time::{Duration, Instant},
    io::Write,
    fs::{self, OpenOptions},
    env,
};

use serde::{Deserialize, Serialize};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus, Corpus},
    events::SimpleEventManager,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasMutatorBytes, ListInput, MultipartInput},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, list::generic_list_input_mutators, HavocScheduledMutator},
    observers::Observer,
    schedulers::RandScheduler,
    stages::mutational::StdMutationalStage,
    state::{StdState, HasSolutions},
    Error, Evaluator,
};

use libafl_bolts::{
    rands::StdRand,
    tuples::{tuple_list, Merge},
    Named,
    current_nanos,
};

use libafl_qemu::{
    elf::EasyElf,
    modules::SnapshotModule,
    ArchExtras, Emulator, GuestAddr, MmapPerms, Qemu, QemuExecutor, QemuExitReason, Regs,
    TargetSignalHandling,
};

use libafl_qemu::qemu::QemuHooks;

use rand::Rng;

const MAIN_SYMBOL: &str = "main";

// input: arg list with usize representing the index
type FuzzInput = MultipartInput<BytesInput, usize>;

const MAX_ARGS: usize = 64; // maximum number of argument
const MAX_ARG_LEN: usize = 4096; // maximum length for each arg
const PTR: usize = std::mem::size_of::<u64>();

// max region size for argv
fn argv_region_size(arg_read_length: usize) -> usize {
    (MAX_ARGS + 2) * PTR + MAX_ARGS * (MAX_ARG_LEN.max(arg_read_length) + 1)
}

// Represents each function readed from the json file
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TargetConfig {
    name: String,
    d_call: f64,
    solutions: Vec<Vec<Vec<u8>>>,
    is_objective: bool,
    #[serde(default)]
    constrained: Vec<Vec<u8>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FuzzerConfig {
    pub binary_name: String,
    pub arg_read_length: usize,
    // Minimum number of arguments always passed to the binary (if the input contains fewer, empty strings are appended). 
    // This is needed for binaries that read argv[i] without
    // checking argc: if argc is too low, argv[i] == NULL and the target crashes with a segfault.
    #[serde(default = "default_min_args")]
    pub min_args: usize,
    pub targets: Vec<TargetConfig>,
}

fn default_min_args() -> usize {
    1
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ExecState {
    last_hit: Option<TargetConfig>,
    captured_args: Vec<Vec<u8>>,
    arg_read_length: usize,
    #[serde(skip)]
    targets_map: HashMap<u64, TargetConfig>,
}

#[derive(Default, Debug)]
struct BestTest {
    fitness: f64,
    input: Option<FuzzInput>,
    target: Option<TargetConfig>,
    captured_args: Vec<Vec<u8>>,
}

fn args_to_strings(input: &FuzzInput) -> Vec<String> {
    input
        .parts()
        .iter()
        .map(|(_, p)| {
            let bytes = p.mutator_bytes();

            // string format
            let mut escaped = String::new();
            for &b in &bytes[..bytes.len()] {
                // escape_default converts non-printable bytes into \xNN or similar formats.
                for c in std::ascii::escape_default(b) {
                    escaped.push(c as char);
                }
            }

            // hex format
            let hex = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            format!("String: {}, hex: [{}]", escaped, hex)
        })
        .collect()
}

fn format_captured_arg(bytes: &[u8]) -> String {
    // if len is 8 it is probably an integer (not a pointer)
    if bytes.len() == 8 {
        // Convert little-endian bytes to an int
        let val = i64::from_le_bytes(bytes.try_into().unwrap());
        let uval = val as u64;
        
        // print in dec and in hex
        format!("Int: {} (0x{:x})", val, uval)
    } else {    // it is probably a pointer
        // 1. hex representation (for int*, ...)
        let hex_str = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");
            
        // 2. string representation (for char*)
        let mut escaped_str = String::new();
        for &b in &bytes[..bytes.len()] {
            for c in std::ascii::escape_default(b) {
                escaped_str.push(c as char);
            }
        }
        format!("Mem: [Hex: {}] [Str: {}]", hex_str, escaped_str)
    }
}

fn make_seed(args: &[&[u8]]) -> FuzzInput {
    ListInput::new(
        args.iter()
            .enumerate()
            .map(|(i, a)| (i, BytesInput::new(a.to_vec())))
            .collect(),
    )
}

fn generate_initial_seeds() -> Vec<FuzzInput> {
    const NUM_SEEDS: usize = 4;
    const MIN_ARGS: usize = 1;
    const MAX_ARGS: usize = 4;

    let lengths = [8, 16, 32, 64, 128, 264, 526];
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let mut rng = rand::rng();

    (0..NUM_SEEDS)
        .map(|_| {
            let num_args = rng.random_range(MIN_ARGS..=MAX_ARGS);

            let args: Vec<Vec<u8>> = (0..num_args)
                .map(|_| {
                    let length = lengths[rng.random_range(0..lengths.len())];

                    (0..length)
                        .map(|_| charset[rng.random_range(0..charset.len())])
                        .collect()
                })
                .collect();

            let args: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();

            make_seed(&args)
        })
        .collect()
}

// Builds the entire argv region in host memory: 
// [argv0, argv1, ..., argvN, NULL][string1\0.. string2\0.. ...] 
// and returns (blob, argc). base is the guest address where the blob will be written. 
// If the input contains fewer than min_args arguments, the missing ones are empty strings. 
// Each string is NUL-padded to at least pad bytes: this ensures that the hook, which reads 
// arg_read_length bytes from the pointer, does not spill over into the next argument.
fn build_argv(
    input: &FuzzInput,
    argv0: u64,
    base: u64,
    pad: usize,
    min_args: usize,
) -> (Vec<u8>, u64) {
    let mut args: Vec<&[u8]> = input
        .parts()
        .iter()
        .take(MAX_ARGS)
        .map(|(_, p)| {
            let b = p.mutator_bytes();
            &b[..b.len().min(MAX_ARG_LEN)]
        })
        .collect();
    // Ensures that argv[1..=min_args] are never NULL
    while args.len() < min_args.min(MAX_ARGS) {
        args.push(&[]);
    }

    let slot = |a: &[u8]| (a.len() + 1).max(pad);

    let argc = 1 + args.len();
    let header = (argc + 1) * PTR;
    let mut blob = Vec::with_capacity(header + args.iter().map(|a| slot(a)).sum::<usize>());

    blob.extend_from_slice(&argv0.to_le_bytes());
    let mut off = header;
    for a in &args {
        blob.extend_from_slice(&(base + off as u64).to_le_bytes());
        off += slot(a);
    }
    blob.extend_from_slice(&0u64.to_le_bytes()); // argv[argc] = NULL
    for a in &args {
        blob.extend_from_slice(a);
        blob.resize(blob.len() + slot(a) - a.len(), 0);
    }
    (blob, argc as u64)
}

fn to_bit<T>(args: &[T]) -> Vec<String>
where
    T: AsRef<[u8]>,
{
    args.iter()
        .map(|arg| {
            arg.as_ref()
                .iter()
                // insert a padding?
                .map(|&byte| format!("{:08b}", byte))
                //.map(|&byte| format!("{:b}", byte))
                .collect()
        })
        .collect()
}

fn binary_string_distance(a: &str, b: &str, mask: &[u8]) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let max_len = a_bytes.len().max(b_bytes.len());

    (0..max_len)
        // consider only the bits with the corresponding byte constrained (==1)
        .filter(|&k| {
            let byte_idx = k / 8;
            mask.get(byte_idx).copied().unwrap_or(0) == 1
        })
        // take only the mismatches
        .filter(|&k| a_bytes.get(k) != b_bytes.get(k))
        .count()
}

fn distance_binary(target: &[String], value: &[String], constrained: &[Vec<u8>]) -> usize {
    target
        .iter()
        .zip(value.iter())
        .enumerate()
        .map(|(i, (t, v))| {
            // check if it is constrained
            let mask = constrained.get(i).map(|m| m.as_slice()).unwrap_or(&[]);
            binary_string_distance(t, v, mask)
        })
        .sum()
}

fn minimum_distance(input: &[Vec<u8>], solutions: &[Vec<Vec<u8>>], constrained: &[Vec<u8>]) -> usize {
    let input_bits = to_bit(input);

    solutions
        .iter()
        .map(|solution| {
            let solution_bits = to_bit(solution);
            distance_binary(&solution_bits, &input_bits, constrained)
        })
        .min()
        .unwrap_or(usize::MAX)
}

fn compute_fitness(last_hit: Option<&TargetConfig>, arg_bytes: &[Vec<u8>]) -> f64 {
    let target = match last_hit {
        Some(t) => t,
        None => return f64::MAX,
    };

    let d_call = target.d_call;

    let d_step = minimum_distance(arg_bytes, &target.solutions, &target.constrained);

    let m = 1.0 - (1.0 / (d_step as f64 + 10.0).log10());
    d_call + m
}

fn default_exec_state() -> Rc<RefCell<ExecState>> {
    Rc::new(RefCell::new(ExecState::default()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LastFunctionObserver {
    name: Cow<'static, str>,
    #[serde(skip, default = "default_exec_state")]
    exec_state: Rc<RefCell<ExecState>>,
}

impl LastFunctionObserver {
    fn new(exec_state: Rc<RefCell<ExecState>>) -> Self {
        Self {
            name: Cow::Borrowed("last_function_observer"),
            exec_state,
        }
    }

    fn get_exec_state(&self) -> ExecState {
        self.exec_state.borrow().clone()
    }
}

impl Named for LastFunctionObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for LastFunctionObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        let mut exec = self.exec_state.borrow_mut();
        exec.last_hit = None;
        exec.captured_args.clear();
        Ok(())
    }
}

#[derive(Debug)]
struct StagedDistanceFeedback {
    name: Cow<'static, str>,
    best_fitness: f64,
    best_test_state: Rc<RefCell<BestTest>>,
}

impl StagedDistanceFeedback {
    fn new(best_test_state: Rc<RefCell<BestTest>>) -> Self {
        Self {
            name: Cow::Borrowed("staged_distance"),
            best_fitness: f64::MAX,
            best_test_state,
        }
    }
}

impl Named for StagedDistanceFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, S> Feedback<EM, FuzzInput, (LastFunctionObserver, ()), S> for StagedDistanceFeedback {
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &FuzzInput,
        observers: &(LastFunctionObserver, ()),
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let exec = observers.0.get_exec_state();
        let last_fn = exec.last_hit.as_ref();
        let arg_bytes = &exec.captured_args;

        let fitness = compute_fitness(last_fn, arg_bytes);

        if fitness < self.best_fitness {
            // new best test
            let mut bt = self.best_test_state.borrow_mut();
            bt.fitness = fitness;
            bt.input = Some(input.clone());
            bt.target = last_fn.cloned();
            bt.captured_args = arg_bytes.clone();

            let arg_strings: Vec<String> = arg_bytes
                .iter()
                .map(|arg| format_captured_arg(arg))
                .collect();

            let fn_name = last_fn.map(|t| t.name.as_str()).unwrap_or("None");

            println!(
                "[feedback] NEW BEST FITNESS: {:.4} -> {:.4} (Last Function: {}, Captured Arg: {:?}, Input: {:?})",
                self.best_fitness,
                fitness,
                fn_name,
                arg_strings,
                args_to_strings(input)
            );
            self.best_fitness = fitness;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<S> StateInitializer<S> for StagedDistanceFeedback {}

#[derive(Debug)]
struct VulnerabilityObjective {
    name: Cow<'static, str>,
}

impl VulnerabilityObjective {
    fn new() -> Self {
        Self {
            name: Cow::Borrowed("vuln_objective"),
        }
    }
}

impl Named for VulnerabilityObjective {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, S> Feedback<EM, FuzzInput, (LastFunctionObserver, ()), S> for VulnerabilityObjective {
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &FuzzInput,
        observers: &(LastFunctionObserver, ()),
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let exec = observers.0.get_exec_state();
        let arg_bytes = &exec.captured_args;

        // take last hit function
        if let Some(target) = exec.last_hit.as_ref() {
            if target.is_objective {
                let d_step = minimum_distance(arg_bytes, &target.solutions, &target.constrained) as f64;
                if d_step == 0.0 {
                    let arg_strings: Vec<String> = arg_bytes
                        .iter()
                        .map(|arg| format_captured_arg(arg))
                        .collect();
                    println!(
                        "[OBJECTIVE SOLVED] Captured Arg: {:?}, Input: {:?}",
                        arg_strings,
                        args_to_strings(input)
                    );

                    fs::create_dir_all("./solutions").unwrap();
                    
                    let mut file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("./solutions/poc.txt")
                        .unwrap();

                    writeln!(file, "Target function: {}", target.name).unwrap();
                    writeln!(file, "Input: {:?}", args_to_strings(input)).unwrap();
                    
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

impl<S> StateInitializer<S> for VulnerabilityObjective {}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let timeout_secs: u64 = args.iter().skip(1).find_map(|a| a.parse().ok()).unwrap_or(3600);
    println!("[+] Fuzzing with timeout of {} seconds...", timeout_secs);

    let json_data =
        std::fs::read_to_string("targets.json").expect("Impossibile leggere targets.json");
    let config: FuzzerConfig = serde_json::from_str(&json_data).expect("JSON malformato");

    let exec_state = Rc::new(RefCell::new(ExecState::default()));
    let exec_state_harness = exec_state.clone();

    let binary_name = &config.binary_name;
    exec_state.borrow_mut().arg_read_length = config.arg_read_length;
    let targets = config.targets;
    let arg_read_length = config.arg_read_length;
    let min_args = config.min_args;
    let region_size = argv_region_size(arg_read_length);

    let qemu_args = vec!["distance_qemu".to_string(), binary_name.to_string()];

    let emulator = Emulator::empty()
        .qemu_parameters(qemu_args)
        .modules(tuple_list!(SnapshotModule::new()))
        .build()?;

    emulator.set_target_crash_handling(&TargetSignalHandling::RaiseSignal);
    let qemu = emulator.qemu();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)
        .map_err(|e| Error::unknown(format!("ELF parse error: {e:?}")))?;

    let main_addr = elf.resolve_symbol(MAIN_SYMBOL, qemu.load_addr()).unwrap();

    // Hook to trace functions
    unsafe extern "C" fn on_target_hit(data: *const RefCell<ExecState>, pc: GuestAddr) {
        let mut state = (*data).borrow_mut();

        let target = match state.targets_map.get(&(pc as u64)) {
            Some(t) => t.clone(),
            None => return,
        };

        state.last_hit = Some(target.clone());
        state.captured_args.clear();

        let len = target.solutions.first().map_or(0, |sol| sol.len());

        if let Some(qemu) = Qemu::get() {
            if target.name == "main" {
                // for main function I need to handle char** argv
                if let Ok(argv_ptr) = qemu.read_function_argument(1) {
                    // read the argumnets
                    for i in 1..=len {
                        let mut ptr_buf = [0u8; PTR];
                        let arg_entry_addr = argv_ptr + (i * PTR) as u64;

                        if qemu.read_mem(arg_entry_addr as GuestAddr, &mut ptr_buf).is_ok() {
                            let str_ptr = u64::from_le_bytes(ptr_buf);
                            let mut buf = vec![0u8; state.arg_read_length];

                            if str_ptr != 0 && qemu.read_mem(str_ptr as GuestAddr, &mut buf).is_ok() {
                                state.captured_args.push(buf);
                            } else {
                                state.captured_args.push(Vec::new());
                            }
                        } else {
                            state.captured_args.push(Vec::new());
                        }
                    }
                }
            } else {
                for i in 0..len {
                    if let Ok(arg_ptr) = qemu.read_function_argument(i as u8) {
                        let mut buf = vec![0u8; state.arg_read_length];
                        if qemu.read_mem(arg_ptr as GuestAddr, &mut buf).is_ok() {  // it's a pointer
                            state.captured_args.push(buf);
                        } else {    // it's a basic type: I convert to bytes
                            let val_bytes = arg_ptr.to_le_bytes().to_vec();
                            state.captured_args.push(val_bytes);
                        }
                    } else {
                        state.captured_args.push(Vec::new());
                    }
                }
            }
        }
    }

    let hooks = QemuHooks::get().expect("QemuHooks not initialized");
    let exec_state_ptr: *const RefCell<ExecState> = Rc::as_ptr(&exec_state);

    {
        let mut state = exec_state.borrow_mut();
        for target in targets {
            if let Some(addr) = elf.resolve_symbol(&target.name, qemu.load_addr()) {
                state.targets_map.insert(addr as u64, target);
            }
        }
    }

    for &addr in exec_state.borrow().targets_map.keys() {
        unsafe {
            hooks.add_instruction_hooks(exec_state_ptr, addr, on_target_hit, true);
        }
    }

    // Exec until main
    qemu.set_breakpoint(main_addr);
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(addr)) if addr == main_addr => {
                println!("[+] Breakpoint main @ {:#x}", addr);
            }
            res => panic!("Cannot reach main {:?}", res),
        }
    }
    qemu.remove_breakpoint(main_addr);

    let return_addr: u64 = qemu.read_return_address().unwrap();
    qemu.set_breakpoint(return_addr);

    // original argv[0]
    let argv_ptr: u64 = qemu
        .read_function_argument(1)
        .expect("Impossible to read argv");
    let mut ptr_buf = [0u8; PTR];
    qemu.read_mem(argv_ptr, &mut ptr_buf)
        .expect("Impossible to read argv[0]");
    let argv0_ptr = u64::from_le_bytes(ptr_buf);

    // Regione guest for argv
    let argv_region: u64 = qemu
        .map_private(0, region_size, MmapPerms::ReadWrite)
        .expect("map_private failed") as u64;
    println!(
        "[+] argv region mapped @ {:#x} ({} byte)",
        argv_region, region_size
    );

    // stack pointer at the beginning of main
    let stack_ptr: u64 = qemu.read_reg(Regs::Sp).unwrap();
    let best_test = Rc::new(RefCell::new(BestTest {
        fitness: f64::MAX,
        ..Default::default()
    }));

    let last_fn_observer = LastFunctionObserver::new(exec_state.clone());
    let mut feedback = StagedDistanceFeedback::new(best_test.clone());
    let mut objective = VulnerabilityObjective::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<FuzzInput>::new(),
        OnDiskCorpus::new("./solutions")?,
        &mut feedback,
        &mut objective,
    )?;

    let mut manager = SimpleEventManager::new(SimpleMonitor::new(|msg| println!("{msg}")));
    let mut fuzzer = StdFuzzer::new(RandScheduler::new(), feedback, objective);

    let mut harness = move |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                            _state: &mut _,
                            input: &FuzzInput|
          -> ExitKind {
        let qemu = emulator.qemu();
        {
            let mut state = exec_state_harness.borrow_mut();
            state.last_hit = None;
            state.captured_args.clear();
        }

        // 1. argv injection
        let (blob, argc) = build_argv(input, argv0_ptr, argv_region, arg_read_length, min_args);
        if qemu.write_mem(argv_region, &blob).is_err() {
            return ExitKind::Crash;
        }

        // 2. registers restoration
        if qemu.write_reg(Regs::Pc, main_addr).is_err()
            || qemu.write_reg(Regs::Sp, stack_ptr).is_err()
            || qemu.write_reg(Regs::Rdi, argc).is_err()
            || qemu.write_reg(Regs::Rsi, argv_region).is_err()
        {
            return ExitKind::Crash;
        }

        // 3. execution
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(addr)) if addr == return_addr => ExitKind::Ok,
                Ok(QemuExitReason::Crash) => ExitKind::Crash,
                Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
                _ => ExitKind::Crash,
            }
        }
    };

    let mut executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(last_fn_observer),
        &mut fuzzer,
        &mut state,
        &mut manager,
        Duration::from_secs(1),
    )?;

    let initial_seeds = generate_initial_seeds();

    for seed in initial_seeds {
        fuzzer.evaluate_input(&mut state, &mut executor, &mut manager, &seed)?;
    }

    let mutator = HavocScheduledMutator::new(havoc_mutations().merge(generic_list_input_mutators()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let timeout = Duration::from_secs(timeout_secs);
    let start_time = Instant::now();
    let mut timeout_reached = false;

    while state.solutions().is_empty() {
        if start_time.elapsed() >= timeout {
            timeout_reached = true;
            break;
        }
        fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)?;
    }

    if timeout_reached {
        println!("\n[!] Timeout reached.");
        println!("[!] Saving best test in ./solutions/quasi-poc.txt\n");

        let bt = best_test.borrow();
        
        if let (Some(input), Some(target)) = (&bt.input, &bt.target) {
            fs::create_dir_all("./solutions").unwrap();
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("./solutions/quasi-poc.txt")
                .unwrap();

            let arg_strings: Vec<String> = bt.captured_args.iter()
                .map(|a| format_captured_arg(a))
                .collect();
            
            writeln!(file, "Best fitness : {:.4}", bt.fitness).unwrap();
            writeln!(file, "Last function    : {}", target.name).unwrap();
            writeln!(file, "Captured args: {:?}", arg_strings).unwrap();
            writeln!(file, "Input  : {:?}", args_to_strings(input)).unwrap();
        }
    } else {
        println!("[!] Solution found.");
    }

    Ok(())
}