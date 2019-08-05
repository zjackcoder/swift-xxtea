//
//  ViewController.swift
//  TestXXTEA
//
//  Created by 郑嘉杰 on 2019/8/5.
//  Copyright © 2019 郑嘉杰. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }


    @IBAction func onBtnDown(_ sender: UIButton) {
        
        var s1 = String("我是你爸爸！！")
        var key = String("00000000000000")
        var s1Bytes = [UInt8](s1.data(using: String.Encoding.utf8)!)
        var keyBytes = [UInt8](key.data(using: String.Encoding.utf8)!)
        
        var enc = XXTEA.xxteaEncrypt(data: s1Bytes, key: keyBytes)
        
        print("加密后字节：\(enc)")
        
        var dec = XXTEA.xxteaDecrypt(data: enc!, key: keyBytes)!
        
        var res = String.init(cString: &dec)
        
         print("解密输出：\(res)")
    }
}

