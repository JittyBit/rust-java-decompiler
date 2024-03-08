#[allow(clippy::unused_variables)]
mod java_stuff {
    use std::{fmt::Debug, fs, iter::zip, str::FromStr};

    const MAGIC: u32 = 0xCAFEBABE;

    const CONSTANT_UTF8: u8                 =  1;
    const CONSTANT_INTEGER: u8              =  3;
    const CONSTANT_FLOAT: u8                =  4;
    const CONSTANT_LONG: u8                 =  5;
    const CONSTANT_DOUBLE: u8               =  6;
    const CONSTANT_CLASS: u8                =  7;
    const CONSTANT_STRING: u8               =  8;
    const CONSTANT_FIELDREF: u8	            =  9;
    const CONSTANT_METHODREF: u8            = 10;
    const CONSTANT_INTERFACE_METHODREF: u8  = 11;
    const CONSTANT_NAME_AND_TYPE: u8        = 12;
    const CONSTANT_METHOD_HANDLE: u8        = 15;
    const CONSTANT_METHOD_TYPE: u8          = 16;
    const CONSTANT_INVOKE_DYNAMIC: u8       = 18;

    const ATTR_CONSTANT_VALUE: &str    = "ConstantValue";
    const ATTR_CODE: &str              = "Code";
    const ATTR_EXCEPTIONS: &str        = "Exceptions";
    const ATTR_INNER_CLASSES: &str     = "InnerClasses";
    const ATTR_SYNTHETIC: &str         = "Synthetic";
    const ATTR_SOURCE_FILE: &str       = "SourceFile";
    const ATTR_LINE_NUMBER_TABLE: &str = "LineNumberTable";
    //const ATTR_BOOTSTRAP_METHODS: &str = "BootstrapMethods_attribute";

    const OP_NOP: u8            = 0x00; //   0
    const OP_ACONST_NULL: u8    = 0x01; //   1
    const OP_ICONST_M1: u8      = 0x02; //   2
    const OP_ICONST_0: u8       = 0x03; //   3
    const OP_ICONST_5: u8       = 0x08; //   8
    const OP_LCONST_1: u8       = 0x0a; //  10
    const OP_FCONST_0: u8       = 0x0b; //  11
    const OP_FCONST_2: u8       = 0x0d; //  13
    const OP_DCONST_0: u8       = 0x0e; //  14
    const OP_DCONST_1: u8       = 0x0f; //  15
    const OP_BIPUSH: u8         = 0x10; //  16
    const OP_LDC: u8            = 0x12; //  18
    const OP_LDC_W: u8          = 0x13; //  19
    const OP_ALOAD_0: u8        = 0x2a; //  42
    const OP_ALOAD_3: u8        = 0x2d; //  45
    const OP_ARETURN: u8        = 0xb0; // 176
    const OP_RETURN: u8         = 0xb1; // 177
    const OP_GETSTATIC: u8      = 0xb2; // 178
    const OP_PUTFIELD: u8       = 0xb5; // 181
    const OP_INVOKE_VIRTUAL: u8 = 0xb6; // 182
    const OP_INVOKE_SPECIAL: u8 = 0xb7; // 183

    const ACC_FLAGS_MASKS: [u16; 13] = [
        0b0000_0000_0000_0001, // ACC_PUBLIC     = 0x0001 
        0b0000_0000_0000_0010, // ACC_PRIVATE    = 0x0002 
        0b0000_0000_0000_0100, // ACC_PROTECTED  = 0x0004
        0b0000_0000_0000_1000, // ACC_STATIC     = 0x0008 
        0b0000_0000_0001_0000, // ACC_FINAL      = 0x0010 
        0b0000_0000_0010_0000, // ACC_SUPER      = 0x0020
        0b0000_0000_0100_0000, // ACC_VOLATILE   = 0x0040 
        0b0000_0000_1000_0000, // ACC_TRANSIENT  = 0x0080 
        0b0000_0010_0000_0000, // ACC_INTERFACE  = 0x0200
        0b0000_0100_0000_0000, // ACC_ABSTRACT   = 0x0400
        0b0001_0000_0000_0000, // ACC_SYNTHETIC  = 0x1000
        0b0010_0000_0000_0000, // ACC_ANNOTATION = 0x2000
        0b0100_0000_0000_0000  // ACC_ENUM       = 0x4000
    ];

    const ACC_FLAGS: [&str; 13] = [
        "PUBLIC",
        "PRIVATE",
        "PROTECTED",
        "STATIC",
        "FINAL",
        "SUPER",
        "VOLATILE",
        "TRANSIENT",
        "INTERFACE",
        "ABSTRACT",
        "SYNTHETIC",
        "ANNOTATION",
        "ENUM"
    ];

    pub trait Flag {
        fn get_flags(&self) -> Vec<String>;
    }

    // generic 64-bit number trait
    trait Num64: Copy {}
    impl Num64 for u64 {}
    impl Num64 for f64 {}

    #[derive(Debug, Clone)]
    #[allow(clippy::unused_variables)]
    enum ConstInfo {
        Class { name_index: u16 }, // Class_info, String_info
        Member { class_index: u16, name_and_type_index: u16 }, // Fieldref_info, Methodref_info, InterfaceMethodref_info
        String { string_index: u16 },
        Num32 { bytes: u32 },                                  // Integer_info, Float_info
        Num64 { high_bytes: u32, low_bytes: u32 },             // Long_info, Double_info
        NameAndType { name_index: u16, desc_index: u16 },
        Utf8 { length: u16, string: String },
        MethodHandle { ref_kind: u8, ref_index: u16 },
        MethodType { desc_index: u16 },
        InvokeDynamic { bootstrap_method_attr_index: u16, name_and_type_index: u16 },
        NULL
    }

    #[derive(Debug, Clone)]
    pub struct CpInfo {
        tag: u8,
        info: ConstInfo
    }

    impl CpInfo {
        pub fn get_tag(&self) -> u8 {
            self.tag
        }

        fn to_string(&self) -> String {
            match self.info.clone() {
                ConstInfo::Num32 { bytes } => match self.tag {
                    CONSTANT_INTEGER => (bytes as i32).to_string(),
                    CONSTANT_FLOAT => (bytes as f32).to_string(),
                    _ => unreachable!()
                },
                ConstInfo::Num64 { high_bytes, low_bytes } => match self.tag {
                    CONSTANT_LONG => parse_long(high_bytes, low_bytes).to_string(),
                    CONSTANT_DOUBLE => parse_double(high_bytes, low_bytes).to_string(),
                    _ => unreachable!()
                },
                ConstInfo::Utf8 { length: _, string } => string,
                _ => unimplemented!("to_string not implemented for tag={}", self.tag)
            }
        }
    }

    impl CpInfo {
        fn new() -> Self {
            Self {
                tag: 0,
                info: ConstInfo::NULL
            }
        }
    }

    /*
    Not including:
    StackMapTable
    SourceDebugExtension
    LineNumberTable
    LocalVariableTable
    LocalVariableTypeTable
    Deprecated
    EnclosingMethod
    Signature
    SourceFile
    RuntimeVisibleAnnotations
    RuntimeInvisibleAnnotations
    RuntimeVisibleParameterAnnotations
    RuntimeInvisibleParameterAnnotations
    AnnotationDefault
    BootstrapMethods
    */

    // #[derive(Debug)]
    // struct bt_method {
    //     bootstrap_method_ref: u16,
    //     bootstrap_argument_count: u16,
    //     bootstrap_arguments: Vec<u16>
    // }

    #[derive(Debug, Clone)]
    enum AttrInfo { // allowed to ignore some Attributes i think?
        ConstantValue { constvalue_index: u16 },
        Code {
            max_stack: u16,
            max_locals: u16,
            code_len: u32,
            code: Vec<u8>,
            exception_table_len: u16,
            exception_table: Vec<u64>, // start_pc: u2, end_pc: u2, handler_pc: u2, catch_type: u2
            attr_count: u16,
            attributes: Vec<Attribute> // Changed from Attribute -> u16
        },
        LineNumberTable { line_number_len: u16, line_number_tbl: Vec<u32> },
        Exceptions { exception_count: u16, exceptions: Vec<u16> },
        // inner_class_info_index: u2, outer_class_info_index: u2, inner_name_index: u2, inner_class_access_flags: u2
        InnerClasses { class_count: u16, classes: Vec<u64> },
        Synthetic {},
        SourceFile { sourcefile_index: u16 },
        //BootstrapMethods { bootstrap_method_count: u16, bootstrap_methods: Vec<bt_method> },
        NULL
    }

    

    impl crate::java_stuff::AttrInfo {
        pub fn get_code_bytes(&self) -> Option<Vec<u8>> {
            match self {
                AttrInfo::Code { max_stack:_, max_locals:_, code_len:_, code, .. } => {
                    Some(code.to_vec())
                },
                _ => None
            }
        }
    }
    
    #[derive(Debug, Clone)]
    #[allow(clippy::unused_variables)]
    pub struct Attribute {
        name_index: u16,
        attr_len: u32,
        info: AttrInfo
    }

    #[derive(Debug, Clone)]
    #[allow(clippy::unused_variables)]
    pub struct Member { // field_info and method_info merged
        access_flags: u16,
        name_index: u16,
        desc_index: u16,
        attr_count: u16,
        attributes: Vec<Attribute>
    }

    impl Flag for Member{
        fn get_flags(&self) -> Vec<String> {
            get_flags(self.access_flags)
        }
    }

    impl Member {
        pub fn get_code(&self) -> Vec<u8> {
            self.attributes.iter().find_map(|attr| attr.info.get_code_bytes()).expect("Doesn't Contain Code Attribute")
        }
    }

    //TODO: Move the structs into their own module
    // Maybe even move some of the helper methods there too?
    #[derive(Debug)]
    #[allow(clippy::unused_variables)]
    pub struct ClassFile {
        magic: u32,
        minor_version: u16,
        major_version: u16,
        const_pool_count: u16,
        const_pool: Vec<CpInfo>,
        access_flags: u16,
        this_class: u16,      // index into const_pool
        super_class: u16,     // index into const_pool
        interfaces_count: u16,
        interfaces: Vec<u16>, // list of indexes into const_pool
        fields_count: u16,
        pub fields: Vec<Member>,
        methods_count: u16,
        pub methods: Vec<Member>,
        attr_count: u16,
        attributes: Vec<Attribute>
    }

    impl Flag for ClassFile {
        fn get_flags(&self) -> Vec<String> {
            get_flags(self.access_flags)
        }
    }

    impl ClassFile {
        fn get_utf8(&self, index: u16) -> String {
            get_utf8(index, &self.const_pool)
        }
        fn get_member_names(&self, members: &Vec<Member>) -> Vec<String> {
            members.iter().map(|member| self.get_utf8(member.name_index)).collect()
        }
        fn get_member_sig(&self, member: &Member) -> String {
            let (mem_type, params) = parse_desc(&self.get_utf8(member.desc_index));
            (
                member.get_flags().join(" ") + " " + 
                &mem_type + " " + 
                &self.get_utf8(member.name_index) + &params
            ).trim().replace('/', ".").to_string()
        }
        pub fn get_member_desc(&self, member: &Member) -> String {
            self.get_utf8(member.desc_index)
                .replace('L', "")
                .replace('/', ".")
                .replace(';', ",")
                .trim_matches(
                    |c: char| 
                    c.is_whitespace() ||
                    c == '\t'
                )
                .to_string()
        }
        pub fn get_constants(&self) -> Vec<CpInfo> {
            self.const_pool.clone()
        }
        pub fn get_classname(&self) -> String {
            get_classname(self.this_class as usize, &self.const_pool)
        }
        pub fn get_super_classname(&self) -> String {
            get_classname(self.super_class as usize, &self.const_pool)
        }
        pub fn get_interfaces(&self) -> Vec<String> {
            self.interfaces.iter().map(|index: &u16| get_classname(*index as usize, &self.const_pool)).collect()
        }
        pub fn get_fields(&self) -> Vec<String> {
            self.get_member_names(&self.fields)
        }
        pub fn get_methods(&self) -> Vec<String> {
            self.get_member_names(&self.methods)
        }
        pub fn get_fields_full(&self) -> Vec<String> {
            self.fields.clone().iter()
                .map(|field| self.get_member_sig(field))
                .map(|string| string + ";")
                .collect()
        }
        pub fn get_methods_sig(&self) -> Vec<String> {
            self.methods.clone().iter()
                .map(|method| self.get_member_sig(method))
                .collect()
        }
        pub fn get_method_bytecode(&self, member: &Member) -> Vec<String> {
            decompile_code_bytes(&member.get_code())
        }  
    }
    
    fn decompile_code_bytes(bytes: &Vec<u8>) -> Vec<String> {
        //let mut i: u32 = 0;
        let mut i: usize = 0;
        let mut code: Vec<String> = vec![];
        //while i < bytes.len() as u32 {
        while i < bytes.len() {
            let opcode = bytes[i as usize];
            match opcode {
                OP_NOP => code.push("nop".to_string()),
                OP_ACONST_NULL => code.push("aconst_null".to_string()),
                OP_ICONST_M1 => code.push("iconst_m1".to_string()),
                OP_ICONST_0..=OP_ICONST_5 => code.push("iconst_".to_string() + &(opcode-3).to_string()),
                OP_LCONST_1 => code.push("lconst_1".to_string()),
                OP_FCONST_0..=OP_FCONST_2 => code.push("fconst_".to_string() + &(opcode-0xb).to_string()),
                OP_DCONST_0 | OP_DCONST_1 => code.push("dconst_".to_string() + &(opcode-0xe).to_string()),
                OP_BIPUSH => { 
                    code.push("bipush ".to_string() + &bytes[i+1].to_string());
                    i+=1
                },
                OP_LDC => {
                    code.push("ldc #".to_string() + &bytes[i+1].to_string());
                    i+=1
                },
                OP_LDC_W => {
                    code.push("ldc_w #".to_string() + &(parse_u2_be(&bytes[i+1..i+3])).to_string());
                    i+=2
                }
                OP_ALOAD_0..=OP_ALOAD_3 => code.push("aload_".to_string()+&(opcode-42).to_string()),
                OP_ARETURN => code.push("areturn".to_string()),
                OP_RETURN => code.push("return".to_string()),
                OP_GETSTATIC => { 
                    code.push("getstatic #".to_string() + &(parse_u2_be(&bytes[i+1..i+3])).to_string());
                    i+=2
                },
                OP_PUTFIELD => {
                    code.push("putfield #".to_string() + &(parse_u2_be(&bytes[i+1..i+3])).to_string());
                    i+=2
                },
                OP_INVOKE_VIRTUAL => {
                    code.push("invokevirtual #".to_string() + &((bytes[i as usize+1] as u16) << 8 | (bytes[i as usize+2] as u16)).to_string());
                    i+=2
                }
                OP_INVOKE_SPECIAL => {
                    code.push("invokespecial #".to_string() + &((bytes[i as usize+1] as u16) << 8 | (bytes[i as usize+2] as u16)).to_string());
                    i+=2
                },
                
                _ => code.push("unimplemented opcode: ".to_string() + &opcode.to_string())
            }
            i += 1;
        }
        code
    }

    fn parse_u1(bytes: &Vec<u8>, cursor: &mut u32) -> Option<u8> {
        if *cursor >= bytes.len() as u32 {
            return None;
        }

        *cursor += 1;
        Some(bytes[(*cursor - 1) as usize])
    }

    fn parse_u2_be(bytes: &[u8]) -> u16 {
        if bytes.len() != 2 {
            panic!("incorrect number of bytes");
        }
        (bytes[0] as u16) << 8 | (bytes[1] as u16)
    }

    fn parse_u2(bytes: &Vec<u8>, cursor: &mut u32) -> u16 {
        if *cursor >= (bytes.len()-1) as u32 {
            panic!("Not enough bytes to parse u2\ncursor = {}", *cursor);
        }

        *cursor += 2;
        
        u16::from(bytes[(*cursor - 1) as usize]) | 
        u16::from(bytes[(*cursor - 2) as usize]).wrapping_shl(8)
    }

    fn parse_u4(bytes: &Vec<u8>, cursor: &mut u32) -> Option<u32> {
        if *cursor >= (bytes.len()-3) as u32 {
            return None;
        }

        let mut temp: u32 = 0;
        for i in 0..4 {
            let index = (*cursor + i) as usize;
            let byte = bytes.get(index).copied().unwrap() as u32; // Ensure bytes are within bounds
            temp |= byte << (8 * (3 - i)); // Reverse the order of bytes
        }

        *cursor += 4;
        Some(temp)
    }

    fn parse_magic(bytes: &Vec<u8>, cursor: &mut u32) -> u32 {
        let magic = parse_u4(bytes, cursor).expect("Error parsing magic");
        if magic != MAGIC {
            eprintln!("File is not proper java .class file");
            std::process::exit(1);
        }
        magic
    }

    fn parse_u8(bytes: &[u8], cursor: &mut u32) -> Option<u64> {
        if *cursor >= (bytes.len()-7) as u32 {
            return None;
        }

        let mut temp: u64 = 0;
        for i in 0..4 {
            let index = (*cursor + i) as usize;
            let byte = bytes.get(index).copied().unwrap() as u64; // Ensure bytes are within bounds
            temp |= byte << (8 * (3 - i)); // Reverse the order of bytes
        }

        *cursor += 4;
        Some(temp)
    }

    fn parse_long(high_bytes: u32, low_bytes: u32) -> u64 {
        ((high_bytes as u64) << 32) | low_bytes as u64
    }

    fn parse_double(high_bytes: u32, low_bytes: u32) -> f64 {
        parse_long(high_bytes, low_bytes) as f64
    }

    fn parse_constant(bytes: &Vec<u8>, cursor: &mut u32, tag: u8) -> CpInfo {
        match tag {
            CONSTANT_UTF8 => {
                let length = parse_u2(bytes, cursor);
                let string: String = String::from_utf8(bytes[*cursor as usize..(*cursor+length as u32) as usize].to_vec()).unwrap();
                *cursor += length as u32;
                
                CpInfo {
                    tag,
                    info: ConstInfo::Utf8 { 
                        length, 
                        string 
                    }
                }
            }

            CONSTANT_INTEGER | CONSTANT_FLOAT => {
                CpInfo {
                    tag,
                    info: ConstInfo::Num32 { 
                        bytes: parse_u4(bytes, cursor).unwrap()
                    }
                }
            }

            CONSTANT_LONG | CONSTANT_DOUBLE => {
                CpInfo {
                    tag,
                    info: ConstInfo::Num64 { 
                        high_bytes: parse_u4(bytes, cursor).unwrap(),
                        low_bytes: parse_u4(bytes, cursor).unwrap() 
                    }
                }
            }

            CONSTANT_CLASS => {
                CpInfo {
                    tag,
                    info: ConstInfo::Class { 
                        name_index: parse_u2(bytes, cursor)
                    }
                }
            }

            CONSTANT_STRING => {
                CpInfo {
                    tag,
                    info: ConstInfo::String { 
                        string_index: parse_u2(bytes, cursor)
                    }
                }
            }

            CONSTANT_FIELDREF | CONSTANT_METHODREF | CONSTANT_INTERFACE_METHODREF  => {
                CpInfo {
                    tag,
                    info: ConstInfo::Member { 
                        class_index: parse_u2(bytes, cursor), 
                        name_and_type_index: parse_u2(bytes, cursor) 
                    }
                }
            }

            CONSTANT_NAME_AND_TYPE => {
                CpInfo {
                    tag,
                    info: ConstInfo::NameAndType { 
                        name_index: parse_u2(bytes, cursor), 
                        desc_index: parse_u2(bytes, cursor)
                    }
                }
            }

            _ => unimplemented!("tag: {tag}")
        }
    }

    fn parse_attribute(bytes: &Vec<u8>, cursor: &mut u32, name_index: u16, constants: &Vec<CpInfo>) -> Option<Attribute> {
        let attr_len = parse_u4(bytes, cursor).unwrap();
        //println!("Length of {}: {}", get_utf8(name_index, constants), attr_len);
        match get_utf8(name_index, constants).as_str() {
            ATTR_CONSTANT_VALUE => {
                Some(
                    Attribute {
                        name_index,
                        attr_len,
                        info: AttrInfo::ConstantValue { 
                            constvalue_index: parse_u2(bytes, cursor) 
                        }
                    }
                )
            }

            ATTR_SOURCE_FILE => {
                Some(
                    Attribute { 
                        name_index, 
                        attr_len, 
                        info: AttrInfo::SourceFile { 
                            sourcefile_index: parse_u2(bytes, cursor)
                        }
                    }
                )
            }

            ATTR_LINE_NUMBER_TABLE => {
                let ln_num_len: u16;
                Some(
                    Attribute {
                        name_index,
                        attr_len,
                        info: AttrInfo::LineNumberTable { 
                            line_number_len: {
                                ln_num_len = parse_u2(bytes, cursor);
                                ln_num_len
                            }, 
                            line_number_tbl: {
                                //TODO: fill out line number table later
                                *cursor += (ln_num_len*4) as u32;
                                vec![]
                            } 
                        }
                    }
                )
            }

            ATTR_CODE => {
                let code_length: u32;
                let exc_tbl_len: u16;
                let code_attr_len: u16;
                Some(
                    Attribute {
                        name_index,
                        attr_len,
                        info: AttrInfo::Code { 
                            max_stack: parse_u2(bytes, cursor), 
                            max_locals: parse_u2(bytes, cursor), 
                            code_len: {
                                code_length = parse_u4(bytes, cursor).unwrap();
                                code_length
                            }, 
                            code: {
                                let code_slice = bytes[*cursor as usize..(*cursor+code_length) as usize].to_vec();
                                *cursor += code_length;
                                code_slice
                            }, 
                            exception_table_len: {
                                exc_tbl_len = parse_u2(bytes, cursor);
                                exc_tbl_len
                            }, 
                            exception_table: {
                                bytes[*cursor as usize..(*cursor+(exc_tbl_len*8) as u32) as usize]
                                    .chunks(8)
                                    .filter_map(|_chunk| {
                                        let result = parse_u8(bytes, cursor);
                                        *cursor += 8;
                                        result
                                    })
                                    .collect()
                            }, 
                            attr_count: {
                                code_attr_len = parse_u2(bytes, cursor);
                                code_attr_len
                            }, 
                            attributes: parse_attributes(bytes, cursor, code_attr_len, constants)
                        }
                    }
                )
            }

            tag => {
                //unimplemented!("Attribute not implemented: {tag}")
                eprintln!("Attribute not implemented: {tag}");
                *cursor += attr_len;
                None
            }
        }
    }

    pub fn parse_desc(desc: &String) -> (String, String) {
        let mut member_type: String = String::new();
        let mut params: String = String::new();
        let mut is_params: bool = false;
        let mut arr_dim: u8 = 0;
        let mut is_obj: bool = false;
        let mut str_buffer: String = String::new();
        let mut arg_num: u8 = 0;

        for c in desc.chars() {
            match c {
                '(' => {
                    is_params = true;
                    params.push('(')
                },

                ')' => {
                    is_params = false;
                    params.push(')');
                },

                '[' => arr_dim += 1,
                
                'L' => is_obj = true,

                ';' => {
                    is_obj = false;
                    for _i in 0..arr_dim {
                        str_buffer.push_str("[]");
                        arr_dim -= 1
                    }
                    if is_params { 
                        params.push_str(&str_buffer);
                        params.push_str((" arg".to_owned() + &arg_num.to_string()).as_str());
                        params.push_str(", ");
                        arg_num += 1
                    } else {
                        member_type.push_str(&str_buffer)
                    }
                    str_buffer.clear()
                }
                
                'B' | 'C' | 'D' | 'F' | 
                'I' | 'J' | 'S' | 'Z' | 'V'  => {
                    if is_obj { 
                        str_buffer.push(c);
                        continue 
                    }
                    str_buffer.push_str(parse_prim(c));
                    for _i in 0..arr_dim {
                        str_buffer.push_str("[]");
                        arr_dim -= 1;
                    }
                    if is_params {
                        params.push_str(&str_buffer);
                        params.push_str((" arg".to_owned() + &arg_num.to_string()).as_str());
                        params.push_str(", ");
                        arg_num += 1
                    } else {
                        member_type.push_str(&str_buffer)
                    }
                    str_buffer.clear()
                },

                _ => {
                    if is_obj {
                        str_buffer.push(c); 
                        continue 
                    }
                    unreachable!("tf is this??? {}", c)
                }
            }
        }

        fn parse_prim(c: char) -> &'static str {
            match c {
                'B' => "byte",
                'C' => "char",
                'D' => "double",
                'F' => "float",
                'I' => "int",
                'J' => "long",
                'S' => "short",
                'Z' => "boolean",
                'V' => "void",
                 _  => unreachable!("issue here: {}", c)
            }
        }
        (member_type, params.replace(", )", ")"))
    }

    fn parse_constants(bytes: &Vec<u8>, cursor: &mut u32, const_pool_count: u16) -> Vec<CpInfo> {
        (0..const_pool_count-1).map(|_| {
            let tag = parse_u1(bytes, cursor).unwrap();
            parse_constant(bytes, cursor, tag)
        }).collect()
    }

    fn parse_attributes(bytes: &Vec<u8>, cursor: &mut u32, attr_count: u16, const_pool: &Vec<CpInfo>) -> Vec<Attribute>{
        (0..attr_count)
            .map(|_| {
                let name_index = parse_u2(bytes, cursor);
                parse_attribute(bytes, cursor, name_index, const_pool).expect("None attribute")
            }).collect()
    }

    fn parse_members(bytes: &Vec<u8>, cursor: &mut u32, member_count: u16, const_pool: &Vec<CpInfo>) -> Vec<Member> {
        (0..member_count)
            .map(|_| {
                let attr_count: u16;
                Member {
                    access_flags: parse_u2(bytes, cursor),
                    name_index: parse_u2(bytes, cursor),
                    desc_index: parse_u2(bytes, cursor),
                    attr_count: {attr_count = parse_u2(bytes, cursor); attr_count},
                    attributes: parse_attributes(bytes, cursor, attr_count, const_pool)
                }
            }).collect()
    }

    fn get_flags(access_flags: u16) ->  Vec<String> {
        zip(ACC_FLAGS_MASKS.map(|mask| mask & access_flags), ACC_FLAGS)
                .filter(|(mask, _)| *mask > 0)
                .map(|(_, flag)| flag).flat_map(String::from_str)
                .map(|str| str.to_lowercase()).collect()
    }

    fn get_utf8(index: u16, constants: &Vec<CpInfo>) -> String {
        match get_constant(index, constants) {
            Some(constant) => {
                match constant.info {
                    ConstInfo::Utf8 { length: _, string } => {
                        string
                    }
                    _ => unreachable!("index is not a Utf8_info")
                }
            },
            None => unreachable!("constant index out of bounds")
        }
    }

    fn get_constant(index: u16, constants: &Vec<CpInfo>) -> Option<CpInfo> {
        constants.get((index-1) as usize).cloned()
    }

    pub fn get_classname(index: usize, constants: &Vec<CpInfo>) -> String {
        match constants[index-1].info.clone() {
            ConstInfo::Class { name_index } => {
                get_utf8(name_index, constants)
            }
            _ => unreachable!()
        }
    }

    pub fn read_class(filepath: &str) -> ClassFile {
        let mut cursor: u32 = 0;
        let bytes: Vec<u8> = fs::read(filepath).expect("Error reading file");

        let const_pool: Vec<CpInfo>;
        let const_pool_count: u16;
        let interfaces_count: u16;
        let fields_count: u16;
        let methods_count: u16;
        let attr_count: u16;
        ClassFile {
            magic: parse_magic(&bytes, &mut cursor),
            minor_version: parse_u2(&bytes, &mut cursor),
            major_version: parse_u2(&bytes, &mut cursor),
            const_pool_count: {const_pool_count = parse_u2(&bytes, &mut cursor); const_pool_count},
            const_pool: {const_pool = parse_constants(&bytes, &mut cursor, const_pool_count); const_pool.clone()},
            access_flags: parse_u2(&bytes, &mut cursor),
            this_class: parse_u2(&bytes, &mut cursor),
            super_class: parse_u2(&bytes, &mut cursor),
            interfaces_count: {interfaces_count = parse_u2(&bytes, &mut cursor); interfaces_count},
            interfaces: (0..interfaces_count).map(|_| parse_u2(&bytes, &mut cursor)).collect(),
            fields_count: {fields_count = parse_u2(&bytes, &mut cursor); fields_count},
            fields: parse_members(&bytes, &mut cursor, fields_count, &const_pool),
            methods_count: {methods_count = parse_u2(&bytes, &mut cursor); methods_count},
            methods: parse_members(&bytes, &mut cursor, methods_count, &const_pool),
            attr_count: {attr_count = parse_u2(&bytes, &mut cursor); attr_count},
            attributes: parse_attributes(&bytes, &mut cursor, attr_count, &const_pool)
        }

    }
}
use crate::java_stuff::Flag;
use std::iter::zip;

fn main() {
    let filepath = "java_files/Hello.class";
    let hello_class: java_stuff::ClassFile = java_stuff::read_class(filepath);

    print!("\n\n{} {} ", hello_class.get_flags().join(" "), hello_class.get_classname());
    println!("extends {} implements {} {{", 
        hello_class.get_super_classname().replace('/',"."),
        hello_class.get_interfaces().join(", ")
            .replace('/',".").trim_end_matches(", ")
    );
    hello_class.get_fields_full().iter().for_each(|str| println!("\t{}", str));
    println!();
    
    zip(hello_class.get_methods_sig(),hello_class.methods.clone())
        .map(|(sig,method)| 
            (sig,
            hello_class.get_method_bytecode(&method)
                .iter()
                .map(|opcode: &String| "\t\t".to_string() + opcode)
                .collect::<Vec<String>>()
                .join(",\n")
            ) //TODO: use reduce to handle join()?
        )
        .collect::<Vec<(String,String)>>()
        .iter()
        .for_each(|(sig, methods)| println!("\t{sig} {{\n{methods}\n\t}}"));
    
    println!("}}");
    println!("\n")
}