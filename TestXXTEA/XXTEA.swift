//
//  XXTEA.swift
//  iOS_im_base
//
//  Created by worker on 2019/8/5.
//  Copyright © 2019 郑嘉杰. All rights reserved.
//

import Foundation

class XXTEA {
    private static let XXTEA_DELTA : UInt32 = 0x9e3779b9
    
    private static func xxteaMX(z : UInt32, y : UInt32, sum : UInt32, p : Int, e : UInt32, key : [UInt32] ) -> UInt32 {
        //#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
        let p1 : UInt32 = (z>>5^y<<2)
        let p2 : UInt32 = (y>>3^z<<4)
        
        let s1 : UInt32 = (sum^y)
        let i : Int = (p&3) ^ Int(e)
        let k1 : UInt32 = (key[i] ^ z)
        
        let pp = p1 &+ p2
        let sk = s1 &+ k1
        
        return (pp ^ sk)
    }
    
    private static func xxteaUintEncrypt(plainValue : [UInt32], k : [UInt32]) -> [UInt32] {
        let n : Int = plainValue.count
        var y : UInt32 = 0
        var z : UInt32
        var sum : UInt32 = 0
        let rounds : Int = 6 + (52/n)
        var e : UInt32 = 0
        var v : [UInt32] = plainValue
        let pValue = n - 1
        
        z = v[n-1]
        for _ in 0..<rounds {
            
            sum = sum &+ XXTEA_DELTA
            e = (sum >> 2) & 3;
            
            for p in 0..<n-1 {
                y = v[p+1]
                v[p] = v[p] &+ xxteaMX(z: z, y: y, sum: sum, p: p, e: e, key: k)
                z = v[p]
            }
            
            y = v[0]
            v[n-1] = v[n-1] &+ xxteaMX(z: z, y: y, sum: sum, p: pValue, e: e, key: k)
            z = v[n-1]
        }
        
        return v
    }
    
    private static func xxteaUintDecrypt(encryptedValue : [UInt32], k : [UInt32]) -> [UInt32] {
        let n : Int = encryptedValue.count
        let rounds : Int = 6 + 52/n
        var sum : UInt32 = 0
        var v : [UInt32] = encryptedValue
        var y : UInt32 = 0
        var z : UInt32
        var e : UInt32 = 0
        let pValue = 0
        
        sum = UInt32(rounds) &* XXTEA_DELTA;
        y = v[0];
        for _ in 0 ..< rounds {
            e = (sum >> 2) & 3
            
            for p in (1...n-1).reversed() {
                z = v[p-1]
                v[p] =  v[p] &- xxteaMX(z: z, y: y, sum: sum, p: p, e: e, key: k)
                y = v[p]
            }
            
            z = v[n-1]
            v[0] = v[0] &- xxteaMX(z: z, y: y, sum: sum, p: pValue, e: e, key: k)
            y = v[0]
            sum = sum &- XXTEA_DELTA;
        }
        
        return v
    }
    
    
    private static func toUintArray(data:[UInt8], includeLength:Bool)->[UInt32]?{
        let len = data.count
        var out:[UInt32]?
        
        let n:Int = (((len & 3) == 0) ? (len >> 2) : ((len >> 2) + 1))
        if includeLength {
            out = Array<UInt32>.init(repeating: 0, count: n + 1)
            if out == nil {
                return nil
            }
            out![n] = UInt32(data.count)
            
        }else{
            out = Array<UInt32>.init(repeating: 0, count: n)
            if out == nil {
                return nil
            }
        }
        var i:Int = 0
        while i < len {
            out![i >> 2] |= UInt32(data[i]) << ((i & 3) << 3)
            i += 1
        }
        return out
    }
    
    private static func toUByteArray(data:[UInt32], includeLength:Bool)-> [UInt8]?{
        let len = data.count
        var out:[UInt8]?
        
        
        var n:Int = len << 2
        if includeLength {
            let m = data[data.count - 1]
            n -= 4
            if (m < n - 3) || (m > n) {
                return nil
            }
            n = Int(m)
        }
        out = Array<UInt8>.init(repeating: 0, count: n)
        var i:Int = 0
        while i < n {
            var tmp:UInt32 = data[i >> 2] >> ((i & 3) << 3)
            out![i] = [UInt8](Data.init(bytes: &tmp, count: 4))[0]
            i += 1
        }
        //    out![n] = Character("\0").asciiValue!
        return out
    }
    
    private static func xxteaUbyteEncrypt(data:[UInt8], key:[UInt8]) -> [UInt8]?{
        var out:[UInt8]?
        var dataIntArray:[UInt32]?
        var keyIntArray:[UInt32]?
        
        if (data.count == 0){
            return nil
        }
        
        dataIntArray = toUintArray(data: data, includeLength: true)
        if (dataIntArray == nil) {
            return nil
        }
        
        keyIntArray  = toUintArray(data: key, includeLength: false)
        if (keyIntArray == nil) {
            return nil;
        }
        
        out = toUByteArray(data: xxteaUintEncrypt(plainValue: dataIntArray!, k: keyIntArray!), includeLength: false)
        
        return out;
    }
    
    private static func xxteaUbyteDecrypt(data:[UInt8], key:[UInt8])->[UInt8]? {
        var out:[UInt8]?
        var dataIntArray:[UInt32]?
        var keyIntArray:[UInt32]?
        
        if (data.count == 0){
            return nil
        }
        
        dataIntArray = toUintArray(data: data, includeLength: false)
        if (dataIntArray == nil) {
            return nil
        }
        
        keyIntArray  = toUintArray(data: key, includeLength: false)
        if (keyIntArray == nil) {
            return nil;
        }
        
        out = toUByteArray(data: xxteaUintDecrypt(encryptedValue: dataIntArray!, k: keyIntArray!), includeLength: true)
        
        return out;
    }
    
    
    public static func xxteaEncrypt(data:[UInt8], key:[UInt8])->[UInt8]?{
        return xxteaUbyteEncrypt(data: data, key: key)
    }
    
    public static func xxteaDecrypt(data:[UInt8], key:[UInt8])->[UInt8]?{
        return xxteaUbyteDecrypt(data: data, key: key)
    }

}


