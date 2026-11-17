import { configMocks } from 'jsdom-testing-mocks'
import { act } from '@testing-library/react'
import { TextDecoder, TextEncoder } from 'util'

// React Router 7 uses TextEncoder at module load; jsdom does not provide it
Object.assign(globalThis, { TextEncoder, TextDecoder })

// as per jsdom-testing-mocks docs, this is needed to avoid having to wrap everything in act calls
configMocks({ act })
