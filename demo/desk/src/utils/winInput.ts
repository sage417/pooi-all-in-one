import assert from 'node:assert/strict'

// import { sleep } from '@waiting/shared-core'
import {User32} from 'win32-api'
import {INPUT, KEYBDINPUT, VirtualKey} from 'win32-def/consts'
import type {INPUT_Type} from 'win32-def/struct'
import {INPUT_Factory} from 'win32-def/struct'


const { INPUT_KEYBOARD } = INPUT
const { KEYEVENTF_KEYUP } = KEYBDINPUT
const { VK_RWIN } = VirtualKey
const { VK_D } = VirtualKey

const lib = User32.load()

// const events: INPUT_Type[] = [
//   make_keyboard_event(VK_RWIN, true),
//   make_keyboard_event(VK_D, true),
//   make_keyboard_event(VK_D, false),
//   make_keyboard_event(VK_RWIN, false),
// ]

// const { size } = INPUT_Factory()

// const lib = User32.load()
// const res = lib.SendInput(events.length, events, size)
// assert(res === events.length)


function simulateKeyEvent(
  eventType: 'keydown' | 'keyup',
  keyCode: number,
  modifiers: {
    ctrlKey: boolean,
    shiftKey: boolean,
    altKey: boolean,
    metaKey: boolean // Windows键
  }
): void {
  // 创建事件数组
  const events: INPUT_Type[] = []

  // 添加修饰键按下事件（如果需要）
  if (eventType === 'keydown') {
    if (modifiers.ctrlKey) {
      events.push(make_keyboard_event(VirtualKey.VK_CONTROL, true))
    }
    if (modifiers.shiftKey) {
      events.push(make_keyboard_event(VirtualKey.VK_SHIFT, true))
    }
    if (modifiers.altKey) {
      events.push(make_keyboard_event(VirtualKey.VK_MENU, true)) // VK_MENU 是Alt键
    }
    if (modifiers.metaKey) {
      events.push(make_keyboard_event(VirtualKey.VK_LWIN, true)) // 使用左Windows键
    }

    // 添加主键按下事件
    events.push(make_keyboard_event(keyCode, true))
  }
  // 添加键释放事件
  else if (eventType === 'keyup') {
    // 添加主键释放事件
    events.push(make_keyboard_event(keyCode, false))

    // 添加修饰键释放事件（如果之前按下了）
    if (modifiers.metaKey) {
      events.push(make_keyboard_event(VirtualKey.VK_LWIN, false))
    }
    if (modifiers.altKey) {
      events.push(make_keyboard_event(VirtualKey.VK_MENU, false))
    }
    if (modifiers.shiftKey) {
      events.push(make_keyboard_event(VirtualKey.VK_SHIFT, false))
    }
    if (modifiers.ctrlKey) {
      events.push(make_keyboard_event(VirtualKey.VK_CONTROL, false))
    }
  }
  
  // 发送事件
  const { size } = INPUT_Factory()
  const res = lib.SendInput(events.length, events, size)

  // 验证所有事件是否都已发送
  assert(res === events.length, `SendInput 失败: 只发送了 ${res}/${events.length} 个事件`)
}


// Utility
function make_keyboard_event(vk: VirtualKey, down: boolean) {
  const event: INPUT_Type = {
    type: INPUT_KEYBOARD,
    u: {
      ki: {
        wVk: vk,
        wScan: 0,
        dwFlags: down ? 0 : KEYEVENTF_KEYUP,
        time: 0,
        dwExtraInfo: 0,
      },
    },
  }
  return event
}


export function handleKeyboardData(data: ArrayBuffer): void {
  const view = new DataView(data);

  // 解析键盘事件信息
  const eventType = view.getUint8(0) === 0 ? 'keydown' : 'keyup';
  const keyCode = view.getUint16(1, true); // 使用小端字节序

  // 解析修饰键状态
  const modifiers = view.getUint8(3);
  const ctrlKey = (modifiers & 0x01) !== 0;
  const shiftKey = (modifiers & 0x02) !== 0;
  const altKey = (modifiers & 0x04) !== 0;
  const metaKey = (modifiers & 0x08) !== 0;

  // 使用解析出的信息重建键盘事件
  simulateKeyEvent(eventType, keyCode, {
    ctrlKey,
    shiftKey,
    altKey,
    metaKey
  });
}